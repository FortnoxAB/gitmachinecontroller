package websocket

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/protocol"
	"github.com/google/uuid"
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
	WriteAndWait(msg *protocol.WebsocketMessage) (*protocol.WebsocketMessage, error)
}
type writeCh struct {
	body  interface{}
	errCh chan error
	typ   int
	data  []byte
}

type websocketClient struct {
	conn            *websocket.Conn
	tlsClientConfig *tls.Config
	writeJSON       chan writeCh
	writeMessage    chan writeCh
	read            chan []byte
	wg              *sync.WaitGroup
	disconnected    chan error
	connected       chan struct{}
	onConnect       func()
	list            map[string]chan []byte
	listMutex       sync.RWMutex
	sync.RWMutex
}

// New creates a new Websocket.
func NewWebsocketClient() Websocket {
	return &websocketClient{
		writeJSON:    make(chan writeCh),
		writeMessage: make(chan writeCh),
		read:         make(chan []byte, 100),
		wg:           &sync.WaitGroup{},
		disconnected: make(chan error),
		connected:    make(chan struct{}),
		list:         make(map[string]chan []byte),
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
	logrus.Debugf("websocket: connecting to %s", addr)
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
	logrus.Debugf("websocket: connected to %s", addr)
	ws.wasConnected()
	ws.Lock()
	ws.conn = c
	ws.Unlock()
	ws.readPump(c)
	ws.writePump(ctx, c) <- struct{}{}

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
	errCh := make(chan error)

	delay := time.NewTimer(time.Millisecond * 10)
	select {
	case ws.writeMessage <- writeCh{errCh: errCh, typ: messageType, data: data}:
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
	errCh := make(chan error)
	delay := time.NewTimer(time.Millisecond * 10)
	select {
	case ws.writeJSON <- writeCh{errCh: errCh, body: v}:
		if !delay.Stop() {
			<-delay.C
		}
	case <-delay.C:
		errCh <- fmt.Errorf("websocket: no one listening on write channel")
	}
	return <-errCh
}
func (ws *websocketClient) WriteAndWait(msg *protocol.WebsocketMessage) (*protocol.WebsocketMessage, error) {

	msg.RequestID = uuid.New().String()

	waitCh := ws.WaitForResponse(msg.RequestID)
	errCh := make(chan error)
	delay := time.NewTimer(time.Millisecond * 10)
	select {
	case ws.writeJSON <- writeCh{errCh: errCh, body: msg}:
		if !delay.Stop() {
			<-delay.C
		}
	case <-delay.C:
		errCh <- fmt.Errorf("websocket: no one listening on write channel")
	}
	err := <-errCh
	if err != nil {
		return nil, err
	}

	rawJson := <-waitCh

	return protocol.ParseMessage(rawJson)
}

func (ws *websocketClient) WaitForResponse(reqID string) chan []byte {
	if ch := ws.Ch(reqID); ch != nil {
		return ch
	}
	ch := make(chan []byte)
	ws.listMutex.Lock()
	ws.list[reqID] = ch
	ws.listMutex.Unlock()
	return ch
}
func (ws *websocketClient) Ch(reqID string) chan []byte {
	ws.listMutex.RLock()
	defer ws.listMutex.RUnlock()
	return ws.list[reqID]
}
func (ws *websocketClient) Done(reqID string) {
	ws.listMutex.Lock()
	delete(ws.list, reqID)
	ws.listMutex.Unlock()
}

func (ws *websocketClient) readPump(conn *websocket.Conn) {
	ws.wg.Add(1)
	type msgWithId struct {
		RequestID string `json:"requestId"`
	}

	go func() {
		defer ws.wg.Done()
		conn.SetReadDeadline(time.Now().Add(pongWait))
		conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				ws.wasDisconnected(err)
				return
			}
			logrus.Debugf("websocket: readPump got msg: %s", message)

			id := &msgWithId{}
			err = json.Unmarshal(message, id)
			if err != nil {
				logrus.Errorf("error parsing RequestID from message: %s", err)
				continue
			}

			if ch := ws.Ch(id.RequestID); ch != nil {
				ch <- message
				ws.Done(id.RequestID)
				continue
			}

			select {
			case ws.read <- message:
			default:
			}
		}
	}()
}

func (ws *websocketClient) writePump(ctx context.Context, conn *websocket.Conn) chan struct{} {
	ready := make(chan struct{})
	ws.wg.Add(1)
	go func() {
		defer ws.wg.Done()
		ticker := time.NewTicker(pingPeriod)
		defer ticker.Stop()
		for {
			select {
			case wc := <-ws.writeJSON:
				wc.errCh <- conn.WriteJSON(wc.body)
			case wc := <-ws.writeMessage:
				wc.errCh <- conn.WriteMessage(wc.typ, wc.data)
			case <-ctx.Done():
				_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(writeWait)); err != nil {
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
	ws.RLock()
	defer ws.RUnlock()
	return ws.conn.Close()
}
