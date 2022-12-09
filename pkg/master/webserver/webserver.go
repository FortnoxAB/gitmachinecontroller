package webserver

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/fortnoxab/ginprometheus"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/jonaz/ginlogrus"
	"github.com/olahol/melody"
	"github.com/sirupsen/logrus"
)

type Webserver struct {
	Port      string
	Websocket *melody.Melody
}

func New(port string) *Webserver {
	return &Webserver{
		Port:      port,
		Websocket: melody.New(),
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

	// api := router.Group("/api")
	// api.POST("/login-v1", TODO)
	router.GET("/pending-machines", err(ws.listPendingMachines))
	router.POST("/api/pending-machines/accept-v1", err(ws.approveMachine))

	ws.initWS(router)

	pprof.Register(router)
	return router
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
			sess.Set("allowed", true)
			logrus.Infof("approved %s", resp.Host)
			err := sess.Write([]byte("nu är du acceptead"))
			if err != nil {
				logrus.Error(err)
				break
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
            <td>{{ . }}</td>
            <td><button onclick="acceptHost('{{.}}')">Accept</button></td>
        </tr>
    {{ end}}
</table>
</body>
</html>`

	tmpl, err := template.New("index").Parse(t)
	if err != nil {
		return err
	}

	hostList := []string{}
	sessions, err := ws.Websocket.Sessions()
	for _, s := range sessions {
		if a, exists := s.Get("allowed"); exists {
			if a, ok := a.(bool); ok && !a {
				host, ok := s.Get("host")
				if !ok {
					logrus.Error("missing host key in websocket session")
					continue
				}
				hostList = append(hostList, host.(string))
			}
		}
	}

	return tmpl.Execute(c.Writer, hostList)
}

func (ws *Webserver) initWS(router *gin.Engine) {
	router.GET("/api/websocket-v1", func(c *gin.Context) {
		keys := make(map[string]interface{})
		// TODO decode this data from JWT
		// TODO make sure we only have one connection from each host.
		keys["host"] = "mimir001.sto1.fnox.se"
		keys["allowed"] = false
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
func TODO(c *gin.Context) {
	c.AbortWithError(500, fmt.Errorf("TODO not implemented"))
}

var jwtKey = []byte("supersecretkey")

type JWTClaim struct {
	Host    string `json:"host"`
	Allowed bool   `json:"allowed"`
	jwt.StandardClaims
}

func ValidateToken(signedToken string) error {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtKey), nil
		},
	)
	if err != nil {
		return fmt.Errorf("auth: error validating: %w", err)
	}

	if !token.Valid {
		return fmt.Errorf("token not valid")
	}

	claims, ok := token.Claims.(*JWTClaim)
	if !ok {
		return fmt.Errorf("couldn't parse claims: ")
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		return fmt.Errorf("token expired")
	}

	return nil
}
