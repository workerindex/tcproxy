package tcproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/yl2chen/cidranger"
	"golang.org/x/sync/errgroup"
	"gopkg.in/option.v0"
)

type configs struct {
	host           string
	port           string
	ranger         cidranger.Ranger
	getForwardConn GetForwardConn
	log            *log.Logger
}

type GetForwardConn func(*net.TCPConn) (net.Conn, error)

type Option func(*configs)

func WithHostPort(host, port string) Option {
	return func(c *configs) {
		c.host = host
		c.port = port
	}
}

func WithCIDRanger(ranger cidranger.Ranger) Option {
	return func(c *configs) {
		c.ranger = ranger
	}
}

func WithForwardConn(fn GetForwardConn) Option {
	return func(c *configs) {
		c.getForwardConn = fn
	}
}

func WithLogger(logger *log.Logger) Option {
	return func(c *configs) {
		c.log = logger
	}
}

var discardLogger = log.New(io.Discard, "", 0)

func WithoutLogger() Option {
	return func(c *configs) {
		c.log = discardLogger
	}
}

func Run(ctx context.Context, options ...Option) (err error) {
	config := option.New[configs](options, WithoutLogger())
	log := config.log
	addr := net.JoinHostPort(config.host, config.port)
	lconf := net.ListenConfig{}
	listener, err := lconf.Listen(ctx, "tcp", addr)
	if err != nil {
		err = fmt.Errorf("failed to listen at address %s: %w", addr, err)
		return
	}
	log.Printf("listening at %s", addr)
	for {
		var conn net.Conn
		if conn, err = listener.Accept(); err != nil {
			err = fmt.Errorf("error accepting new connection: %w", err)
			return
		}
		go func() {
			defer conn.Close()
			addr := conn.RemoteAddr().String()
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return
			}
			if ok, err := config.ranger.Contains(ip); !ok || err != nil {
				log.Printf("reject: %s", addr)
				return
			}
			log.Printf("accept: %s", addr)
			if src, ok := conn.(*net.TCPConn); !ok {
				return
			} else {
				if dst, err := config.getForwardConn(src); err != nil {
					return
				} else {
					defer dst.Close()
					if err := pipe(ctx, src, dst); err != nil {
						log.Printf("error: %s %s", addr, err.Error())
					}
				}
			}
		}()
	}
}

var pool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 64<<10)
	},
}

func pipe(ctx context.Context, srcConn *net.TCPConn, destConn net.Conn) error {
	g := &errgroup.Group{}

	g.Go(func() (err error) {
		defer srcConn.CloseRead()
		if hc, ok := destConn.(closeWriter); ok {
			defer hc.CloseWrite()
		}
		buf := pool.Get().([]byte)
		defer pool.Put(buf)
		_, err = io.CopyBuffer(destConn, srcConn, buf)
		return
	})

	g.Go(func() (err error) {
		defer srcConn.CloseWrite()
		if hc, ok := destConn.(closeReader); ok {
			defer hc.CloseRead()
		}
		buf := pool.Get().([]byte)
		defer pool.Put(buf)
		_, err = io.CopyBuffer(srcConn, destConn, buf)
		return
	})

	return g.Wait()
}

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}
