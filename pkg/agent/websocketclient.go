package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 10 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	reconnectWait = 2 * time.Second
)

// Websocket implements a websocket client.
type Websocket interface {
	OnConnect(cb func())
	ConnectContext(ctx context.Context, addr string, headers http.Header) error
	Wait()
	Read() <-chan []byte
	Disconnected() chan error
	Close() error
	// WriteJSON writes interface{} encoded as JSON to our connection
	WriteJSON(v interface{}) error
	WriteMessage(messageType int, data []byte) error
	SetTLSConfig(c *tls.Config)
}

type websocketClient struct {
	conn            *websocket.Conn
	tlsClientConfig *tls.Config
	write           chan func()
	read            chan []byte
	wg              *sync.WaitGroup
	disconnected    chan error
	connected       chan struct{}
	onConnect       func()
	sync.Mutex
}

// New creates a new Websocket.
func New() Websocket {
	return &websocketClient{
		write:        make(chan func()),
		read:         make(chan []byte, 100),
		wg:           &sync.WaitGroup{},
		disconnected: make(chan error),
		connected:    make(chan struct{}),
	}
}

func (ws *websocketClient) SetTLSConfig(c *tls.Config) {
	ws.tlsClientConfig = c
}

func (ws *websocketClient) OnConnect(cb func()) {
	ws.Lock()
	ws.onConnect = cb
	ws.Unlock()
}

func (ws *websocketClient) getOnConnect() func() {
	ws.Lock()
	defer ws.Unlock()
	return ws.onConnect
}

func (ws *websocketClient) ConnectContext(ctx context.Context, addr string, headers http.Header) error {
	var err error
	var c *websocket.Conn
	logrus.Info("websocket: connecting to ", addr)
	if ws.tlsClientConfig != nil {
		dialer := &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 10 * time.Second,
			TLSClientConfig:  ws.tlsClientConfig,
		}
		c, _, err = dialer.DialContext(ctx, addr, headers)
	} else {
		c, _, err = websocket.DefaultDialer.DialContext(ctx, addr, headers)
	}
	if err != nil {
		ws.wasDisconnected(err)
		return err
	}
	logrus.Infof("websocket: connected to %s", addr)
	ws.wasConnected()
	ws.conn = c
	ws.readPump()
	ws.writePump(ctx) <- struct{}{}

	if oncon := ws.getOnConnect(); oncon != nil {
		oncon()
	}
	return nil
}

func (ws *websocketClient) Wait() {
	ws.wg.Wait()
}

func (ws *websocketClient) Read() <-chan []byte {
	return ws.read
}

func (ws *websocketClient) WriteMessage(messageType int, data []byte) error {
	errCh := make(chan error, 1)

	delay := time.NewTimer(time.Millisecond * 10)
	select {
	case ws.write <- func() {
		err := ws.conn.WriteMessage(messageType, data)
		errCh <- err
	}:
		if !delay.Stop() {
			<-delay.C
		}
	case <-delay.C:
		errCh <- fmt.Errorf("websocket: no one listening on write channel")
	}
	return <-errCh
}

// WriteJSON writes interface{} encoded as JSON to our connection.
func (ws *websocketClient) WriteJSON(v interface{}) error {
	errCh := make(chan error, 1)
	delay := time.NewTimer(time.Millisecond * 10)
	select {
	case ws.write <- func() {
		err := ws.conn.WriteJSON(v)
		errCh <- err
	}:
		if !delay.Stop() {
			<-delay.C
		}
	case <-delay.C:
		errCh <- fmt.Errorf("websocket: no one listening on write channel")
	}
	return <-errCh
}

func (ws *websocketClient) readPump() {
	ws.wg.Add(1)
	go func() {
		defer ws.wg.Done()
		ws.conn.SetReadDeadline(time.Now().Add(pongWait))
		ws.conn.SetPongHandler(func(string) error { ws.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
		for {
			_, message, err := ws.conn.ReadMessage()
			if err != nil {
				ws.wasDisconnected(err)
				return
			}
			logrus.Debugf("websocket: readPump got msg: %s", message)
			select {
			case ws.read <- message:
			default:
			}
		}
	}()
}

func (ws *websocketClient) writePump(ctx context.Context) chan struct{} {
	ready := make(chan struct{})
	ws.wg.Add(1)
	go func() {
		defer ws.wg.Done()
		ticker := time.NewTicker(pingPeriod)
		defer ticker.Stop()
		for {
			select {
			case t := <-ws.write:
				t()
			case <-ctx.Done():
				_ = ws.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			case <-ticker.C:
				if err := ws.conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(writeWait)); err != nil {
					logrus.Error("websocket: ping:", err)
				}
			case <-ready:
			}
		}
	}()
	return ready
}

func (ws *websocketClient) wasDisconnected(err error) {
	select {
	case ws.disconnected <- err:
	default:
	}
}

func (ws *websocketClient) Disconnected() chan error {
	return ws.disconnected
}

func (ws *websocketClient) wasConnected() {
	select {
	case ws.connected <- struct{}{}:
	default:
	}
}
func (ws *websocketClient) Close() error {
	return ws.conn.Close()
}
