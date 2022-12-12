package webserver

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/fortnoxab/ginprometheus"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/protocol"
	"github.com/fortnoxab/gitmachinecontroller/pkg/master/jwt"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/jonaz/ginlogrus"
	"github.com/olahol/melody"
	"github.com/sirupsen/logrus"
)

type Webserver struct {
	Port      string
	Masters   []string
	Websocket *melody.Melody
	jwt       *jwt.JWTHandler
}

func New(port, jwtKey string, masters []string) *Webserver {
	return &Webserver{
		Port:      port,
		Masters:   masters,
		Websocket: melody.New(),
		jwt:       jwt.New(jwtKey),
	}
}

func (ws *Webserver) Init() *gin.Engine {
	router := gin.New()
	p := ginprometheus.New("http")
	p.Use(router)

	logIgnorePaths := []string{
		"/health",
		"/metrics",
		"/readiness",
	}
	router.Use(ginlogrus.New(logrus.StandardLogger(), logIgnorePaths...), gin.Recovery())

	router.GET("/pending-machines", err(ws.listPendingMachines))
	router.POST("/api/pending-machines/accept-v1", err(ws.approveMachine))
	router.GET("/api/up-v1", err(ws.listMasters))

	ws.initWS(router)

	pprof.Register(router)
	return router
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

	sessions, err := ws.Websocket.Sessions()
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		if host, ok := sess.Get("host"); ok && host.(string) == resp.Host {
			logrus.Infof("approved %s", resp.Host)
			token, err := ws.jwt.GenerateJWT(resp.Host)
			if err != nil {
				logrus.Error(err)
				continue
			}
			msg, err := protocol.NewMachineAccepted(resp.Host, token)
			if err != nil {
				logrus.Error(err)
				continue
			}
			err = sess.Write(msg)
			if err != nil {
				logrus.Error(err)
				continue
			}
			break
		}
	}

	return nil
}

// TODO AUTH HÄR OXÅ! hur ska SRE autha sig? Bara med cli o hämta jtw över ssh kanske?
// webserver kanska bara ska lyssna på localhost till en början så måste man ssh proxya?
func (ws *Webserver) listPendingMachines(c *gin.Context) error {
	t := `<!DOCTYPE html>
<html lang="en">
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
    fetch("/api/pending-machines/accept-v1", options);
	location.reload();
}
</script>
<table>
    <tr>
        <th>Name</th>
        <th>Accept</th>
    </tr>
    {{ range .}}
        <tr>
            <td>{{ .Name }}</td>
            <td>{{ .IP }}</td>
            <td><button onclick="acceptHost('{{.Name}}')">Accept</button></td>
        </tr>
    {{ end}}
</table>
</body>
</html>`

	tmpl, err := template.New("index").Parse(t)
	if err != nil {
		return err
	}

	type host struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
	}
	hostList := []*host{}
	sessions, err := ws.Websocket.Sessions()
	for _, s := range sessions {
		if a, exists := s.Get("allowed"); exists {
			if a, ok := a.(bool); ok && !a {
				name, ok := s.Get("host")
				if !ok {
					logrus.Error("missing host key in websocket session")
					continue
				}
				machine := &host{Name: name.(string)}
				if ip, ok := s.Get("ip"); ok {
					machine.IP = ip.(string)
				}
				hostList = append(hostList, machine)
			}
		}
	}

	return tmpl.Execute(c.Writer, hostList)
}

func (ws *Webserver) initWS(router *gin.Engine) {
	router.GET("/api/websocket-v1", func(c *gin.Context) {
		keys := make(map[string]interface{})
		keys["allowed"] = false
		keys["ip"] = c.ClientIP()

		tokenString := c.Request.Header.Get("Authorization")
		if tokenString == "" {
			// TODO do we want to validate src IP compared to the git manifest here?
			hostname := c.Request.Header.Get("X-hostname")
			if hostname == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "missing x-hostname header"})
			}
			keys["host"] = hostname
		} else {
			claims, err := ws.jwt.ValidateToken(tokenString)
			if err != nil {
				c.AbortWithError(http.StatusUnauthorized, err)
				return
			}
			keys["host"] = claims.Host
			keys["allowed"] = claims.Allowed
		}

		// TODO make sure we only have one connection from each host.
		ws.Websocket.HandleRequestWithKeys(c.Writer, c.Request, keys)
	})
}
func (ws *Webserver) Start(ctx context.Context) {
	srv := &http.Server{
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		Addr:              ":" + ws.Port,
		Handler:           ws.Init(),
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Error(err)
		}
	}()

	logrus.Debug("webserver started")

	<-ctx.Done()

	// TODO enable if in k8s
	// logrus.Debug("sleeping 5 sec before shutdown") // to give k8s ingresses time to sync
	// time.Sleep(5 * time.Second)
	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctxShutDown); !errors.Is(err, http.ErrServerClosed) && err != nil {
		logrus.Error(err)
	}
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

var jwtKey = []byte("supersecretkey")
