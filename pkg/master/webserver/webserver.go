package webserver

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/fortnoxab/ginprometheus"
	"github.com/fortnoxab/gitmachinecontroller/pkg/admin"
	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/config"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/protocol"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/fortnoxab/gitmachinecontroller/pkg/master/jwt"
	"github.com/fortnoxab/gitmachinecontroller/pkg/secrets"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/jonaz/ginlogrus"
	"github.com/olahol/melody"
	"github.com/sirupsen/logrus"
)

type Webserver struct {
	Port           string
	Masters        config.Masters
	Websocket      *melody.Melody
	jwt            *jwt.JWTHandler
	MachineStateCh chan types.MachineStateQuestion
	EnableMetrics  bool
	TLSCertFile    string
	TLSKeyFile     string
	TLSPort        string
	secretHandler  *secrets.Handler
}

func New(port, jwtKey string, masters config.Masters, secretHandler *secrets.Handler) *Webserver {
	m := melody.New()
	m.Config.MaxMessageSize = 32 << 20 // 32MB
	return &Webserver{
		Port:          port,
		Masters:       masters,
		Websocket:     m,
		jwt:           jwt.New(jwtKey),
		secretHandler: secretHandler,
	}
}

func (ws *Webserver) Init() *gin.Engine {
	router := gin.New()
	if ws.EnableMetrics {
		p := ginprometheus.New("http")
		p.Use(router)
	}

	logIgnorePaths := []string{
		"/health",
		"/metrics",
		"/readiness",
	}
	router.Use(ginlogrus.New(logrus.StandardLogger(), logIgnorePaths...), gin.Recovery())
	router.GET("/health")
	pprof.Register(router)
	return router
}
func (ws *Webserver) InitTLS() *gin.Engine {
	router := gin.New()
	logIgnorePaths := []string{
		"/health",
		"/metrics",
		"/readiness",
	}
	router.Use(ginlogrus.New(logrus.StandardLogger(), logIgnorePaths...), gin.Recovery())

	router.GET("/", func(c *gin.Context) {
		fmt.Fprintf(c.Writer, `<a href="/machines">Machines</a>`)
	})
	router.GET("/api/up-v1", err(ws.listMasters))
	router.GET("/api/download-v1", err(func(c *gin.Context) error {
		binaryPath, err := admin.GetSelfLocation()
		if err != nil {
			return err
		}

		f, err := os.Open(binaryPath)
		if err != nil {
			return err
		}

		defer f.Close()

		_, err = io.Copy(c.Writer, f)
		return err

	}))
	router.GET("/api/binary-checksum-v1", err(func(c *gin.Context) error {
		f, err := os.Open("/binary-checksum")
		if err != nil {
			return err
		}

		defer f.Close()

		_, err = io.Copy(c.Writer, f)
		return err

	}))
	router.POST("/api/admin-v1", err(ws.createAdmin))

	requireAdmin := router.Group("/")
	requireAdmin.Use(ws.jwt.Middleware())
	requireAdmin.POST("/api/machines/accept-v1", err(ws.approveMachine))
	requireAdmin.POST("/api/secret-encrypt-v1", err(ws.secretEncrypt))
	requireAdmin.GET("/api/authed-v1", func(*gin.Context) {})
	requireAdmin.GET("/machines", err(ws.listPendingMachines))
	requireAdmin.GET("/api/machines-v1", err(func(c *gin.Context) error {

		hostList, err := ws.hostList()
		if err != nil {
			return err
		}

		c.JSON(http.StatusOK, hostList)
		return nil
	}))

	ws.initWS(router)

	return router
}
func (ws *Webserver) secretEncrypt(c *gin.Context) error {

	b, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return err
	}

	defer c.Request.Body.Close()
	secret, err := ws.secretHandler.Encrypt(b)
	if err != nil {
		return err
	}

	_, err = c.Writer.Write(secret)
	return err
}

// func (ws *Webserver) OnWsMsg(fn func(*melody.Session, []byte)) {
// 	ws.Websocket.HandleMessage(fn)
// }

// createAdmin is only allowed to access from localhost or with existing admin JWT.
func (ws *Webserver) createAdmin(c *gin.Context) error {
	ipStr, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return err
	}

	isAdmin := false
	if tokenString := c.Request.Header.Get("Authorization"); tokenString != "" {
		claims, err := ws.jwt.ValidateToken(tokenString)
		if err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)
			return nil
		}
		isAdmin = claims.Admin
	}

	// TODO should we trust some upstream LB for IP?
	isProxy := c.Request.Header.Get("x-forwarded-for") != ""
	ip := net.ParseIP(ipStr)
	if (!ip.IsLoopback() && !isAdmin) || isProxy {
		c.AbortWithError(http.StatusUnauthorized, err)
		return nil
	}

	// TODO add name of the admin person?
	claims := jwt.DefaultClaims(jwt.OptionAdmin())
	token, err := ws.jwt.GenerateJWT(claims)
	if err != nil {
		return err
	}
	c.JSON(http.StatusOK, gin.H{"jwt": token})
	return nil
}

func (ws *Webserver) listMasters(c *gin.Context) error {
	c.JSON(http.StatusOK, gin.H{"masters": ws.Masters})
	return nil
}

func (ws *Webserver) approveMachine(c *gin.Context) error {
	type respStruct struct {
		Host string
	}
	resp := &respStruct{}
	err := c.BindJSON(resp)
	if err != nil {
		return err
	}

	return ws.ApproveAgent(resp.Host)
}

func (ws *Webserver) listPendingMachines(c *gin.Context) error {
	t := `<!DOCTYPE html>
<html lang="en">
<head>
	<style>
		td {padding-right: 25px;}
		tr {text-align: left;}
	</style>
</head>
<body>
<script>
const acceptHost = (hostname) =>  {

    let options = {
        method: "POST",
        headers: {
            "Content-Type":"application/json",
        },
		body: JSON.stringify({host: hostname})
    }
    fetch("/api/machines/accept-v1", options);
	location.reload();
}
</script>
<table>
    <tr>
        <th>Name</th>
        <th>IP</th>
        <th>Online</th>
        <th>Git</th>
        <th>LastGitUpdate</th>
        <th></th>
    </tr>
    {{ range .}}
        <tr>
            <td>{{ .Name }}</td>
            <td>{{ .IP }}</td>
            <td {{if .Online }}style="color:green;"{{else}}style="color:red;"{{end}}>
			{{ .Online }}
			</td>
            <td {{if .Git }}style="color:green;"{{else}}style="color:red;"{{end}}>
			{{ .Git }}
			</td>
            <td>{{ .LastUpdate.Format "2006-01-02T15:04:05Z07:00" }}</td>
            <td>{{if and (not .Accepted) .Online }}<button onclick="acceptHost('{{.Name}}')">Accept</button>{{end}}</td>
        </tr>
    {{ end}}
</table>
</body>
</html>`

	tmpl, err := template.New("index").Parse(t)
	if err != nil {
		return err
	}

	hostList, err := ws.hostList()
	if err != nil {
		return err
	}

	return tmpl.Execute(c.Writer, hostList)
}

type host struct {
	Name       string `json:"name"`
	IP         string `json:"ip"`
	Online     bool
	Accepted   bool
	Git        bool
	LastUpdate time.Time
}

func (ws *Webserver) hostList() (map[string]*host, error) {
	hostList := make(map[string]*host)
	sessions, err := ws.Websocket.Sessions()
	if err != nil {
		return nil, err
	}

	ch := make(chan map[string]*types.MachineState)
	ws.MachineStateCh <- types.MachineStateQuestion{ReplyCh: ch}
	list := <-ch
	for _, h := range list {
		hostList[h.Metadata.Name] = &host{
			Name:       h.Metadata.Name,
			IP:         h.IP,
			LastUpdate: h.LastUpdate,
			Git:        true,
		}
	}

	for _, s := range sessions {
		name, ok := s.Get("host")
		if !ok {
			logrus.Error("missing host key in websocket session")
			continue
		}
		if _, ok := hostList[name.(string)]; !ok {
			hostList[name.(string)] = &host{
				Name: name.(string),
			}
		}

		hostList[name.(string)].Online = true
		if ip, ok := s.Get("ip"); ok {
			hostList[name.(string)].IP = ip.(string)
		}

		allowed, _ := s.Get("allowed")
		if allowed.(bool) {
			hostList[name.(string)].Accepted = allowed.(bool)
			hostList[name.(string)].Online = true
		}
	}
	return hostList, nil
}

func (ws *Webserver) initWS(router *gin.Engine) {
	router.GET("/api/websocket-v1", func(c *gin.Context) {
		keys := make(map[string]any)
		keys["allowed"] = false
		keys["admin"] = false
		keys["ip"] = c.ClientIP()

		tokenString := c.Request.Header.Get("Authorization")
		if tokenString == "" {
			hostname := c.Request.Header.Get("X-hostname")
			if hostname == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "missing x-hostname header"})
				return
			}
			keys["host"] = hostname
		} else {
			claims, err := ws.jwt.ValidateToken(tokenString)
			if err != nil {
				logrus.Errorf("master: error validating jwt: %s", err)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			if keys["ip"] != claims.AllowedIP && !claims.Admin { // Only allow agent to connect from the IP in their JWT
				err = fmt.Errorf("connection from %s forbidden, allowed: %s", keys["ip"], claims.AllowedIP)
				logrus.Errorf("master: error validating jwt: %s", err)
				c.AbortWithError(http.StatusUnauthorized, err)
				return
			}
			keys["admin"] = claims.Admin
			keys["host"] = claims.Host
			keys["allowed"] = claims.Allowed
		}

		err := ws.Websocket.HandleRequestWithKeys(c.Writer, c.Request, keys)
		if err != nil {
			logrus.Errorf("master: error handling websocket: %s", err)
		}
	})
}
func (ws *Webserver) Start(ctx context.Context) {

	go func() {
		srv := &http.Server{
			ReadTimeout:       1 * time.Second,
			WriteTimeout:      1 * time.Second,
			IdleTimeout:       30 * time.Second,
			ReadHeaderTimeout: 2 * time.Second,
			Addr:              ":" + ws.Port,
			Handler:           ws.Init(),
		}
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Fatalf("error starting webserver %s", err)
		}
		<-ctx.Done()

		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" && os.Getenv("KUBERNETES_SERVICE_PORT") != "" {
			logrus.Debug("sleeping 5 sec before shutdown") // to give k8s ingresses time to sync
			time.Sleep(5 * time.Second)
		}
		ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctxShutDown); !errors.Is(err, http.ErrServerClosed) && err != nil {
			logrus.Error(err)
		}
	}()

	//TODO refactor less duplication
	if ws.TLSCertFile != "" && ws.TLSKeyFile != "" {
		srv := &http.Server{
			ReadTimeout:       1 * time.Second,
			WriteTimeout:      1 * time.Second,
			IdleTimeout:       30 * time.Second,
			ReadHeaderTimeout: 2 * time.Second,
			Addr:              ":" + ws.TLSPort,
			Handler:           ws.InitTLS(),
		}
		go func() {
			if err := srv.ListenAndServeTLS(ws.TLSCertFile, ws.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logrus.Fatalf("error starting webserver %s", err)
			}
			<-ctx.Done()

			if os.Getenv("KUBERNETES_SERVICE_HOST") != "" && os.Getenv("KUBERNETES_SERVICE_PORT") != "" {
				logrus.Debug("sleeping 5 sec before shutdown") // to give k8s ingresses time to sync
				time.Sleep(5 * time.Second)
			}
			ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := srv.Shutdown(ctxShutDown); !errors.Is(err, http.ErrServerClosed) && err != nil {
				logrus.Error(err)
			}
		}()
	}

	logrus.Debug("webserver started")

}
func (ws *Webserver) ApproveAgent(hostname string) error {
	sessions, err := ws.Websocket.Sessions()
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		if host, ok := sess.Get("host"); ok && host.(string) == hostname {
			logrus.Infof("approved agent %s", hostname)
			ip, _ := sess.Get("ip")
			token, err := ws.jwt.GenerateJWT(
				jwt.DefaultClaims(
					jwt.OptionHostname(hostname),
					jwt.OptionAllowedIP(ip.(string)),
				))
			if err != nil {
				return err
			}
			msg, err := protocol.NewMachineAccepted(hostname, token)
			if err != nil {
				return err
			}
			err = sess.Write(msg)
			if err != nil {
				return err
			}
			return nil
		}
	}
	return nil
}

func err(f func(c *gin.Context) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := f(c)
		if err != nil {
			logrus.Error(err)
			// TODO handle error messages from 400
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			// c.AbortWithStatus(http.StatusInternalServerError)
		}
	}
}
