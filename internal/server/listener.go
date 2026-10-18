package server

import (
	"net"
	"sync"
)

const MaxConnections = 128

// LimitListener bounds accepted HTTP connections, including clients that never
// finish their headers. Excess connections are closed without starting handlers.
func LimitListener(listener net.Listener, limit int) net.Listener {
	if limit <= 0 {
		panic("connection limit must be positive")
	}
	return &limitedListener{Listener: listener, slots: make(chan struct{}, limit)}
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
