package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"

	"github.com/workerindex/tcproxy/cidr"
	"github.com/workerindex/tcproxy/tcproxy"
	"github.com/yl2chen/cidranger"
	"golang.org/x/sync/errgroup"
)

func init() {
	flag.StringVar(&app.host, "host", "0.0.0.0", "host address to listen")
	flag.StringVar(&app.port, "port", "8888", "host port to listen")
	flag.StringVar(&app.portTLS, "port-tls", "8889", "host port to listen for TLS")
	flag.StringVar(&app.allow, "allow", "", "additional CDIR IP ranges to allow")
	flag.BoolVar(&app.verbose, "verbose", false, "verbose logs")
}

func main() {
	flag.Parse()
	if err := app.run(context.Background()); err != nil {
		panic(err)
	}
}

type App struct {
	host     string
	port     string
	portTLS  string
	allow    string
	dstIP    atomic.Pointer[net.TCPAddr]
	dstIPTLS atomic.Pointer[net.TCPAddr]
	verbose  bool
}

var app App

func (app *App) run(ctx context.Context) (err error) {
	logOption := tcproxy.WithoutLogger()
	if app.verbose {
		logOption = tcproxy.WithLogger(log.Default())
	}
	if err = app.setDefaultCloudflareDestinationIP(ctx); err != nil {
		return
	}
	ranger := cidranger.NewPCTrieRanger()
	if err = fillCloudflareCIDRanger(ranger); err != nil {
		err = fmt.Errorf("failed to load Cloudflare CIDR list: %w", err)
		return
	}
	CIDRs := []string{"127.0.0.1/32"}
	if app.allow != "" {
		CIDRs = append(CIDRs, strings.Split(app.allow, ",")...)
	}
	for _, v := range CIDRs {
		if err = cidr.Add(ranger, v); err != nil {
			err = fmt.Errorf("failed to add CIDR %s: %w", v, err)
			return
		}
	}
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return tcproxy.Run(ctx,
			logOption,
			tcproxy.WithCIDRanger(ranger),
			tcproxy.WithHostPort(app.host, app.port),
			tcproxy.WithForwardConn(app.getForwardConn))
	})
	g.Go(func() error {
		return tcproxy.Run(ctx,
			logOption,
			tcproxy.WithCIDRanger(ranger),
			tcproxy.WithHostPort(app.host, app.portTLS),
			tcproxy.WithForwardConn(app.getForwardConnTLS))
	})
	return g.Wait()
}

func (app *App) getForwardConn(src *net.TCPConn) (dst net.Conn, err error) {
	return net.DialTCP("tcp", nil, app.dstIP.Load())
}

func (app *App) getForwardConnTLS(src *net.TCPConn) (dst net.Conn, err error) {
	return net.DialTCP("tcp", nil, app.dstIPTLS.Load())
}

func (app *App) setDefaultCloudflareDestinationIP(ctx context.Context) (err error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, "www.cloudflare.com")
	if err != nil {
		err = fmt.Errorf("failed to resolve Cloudflare destination IP")
		return
	}
	for _, addr := range addrs {
		if len(addr.IP) == net.IPv4len {
			app.dstIP.Store(&net.TCPAddr{IP: addr.IP, Port: 80})
			app.dstIPTLS.Store(&net.TCPAddr{IP: addr.IP, Port: 443})
			break
		}
	}
	if app.dstIP.Load() == nil {
		err = fmt.Errorf("failed to find a Cloudflare destination IPv4")
		return
	}
	return
}

func fillCloudflareCIDRanger(ranger cidranger.Ranger) (err error) {
	if err = cidr.LoadURL(ranger, "https://www.cloudflare.com/ips-v4"); err != nil {
		err = fmt.Errorf("failed to load Cloudflare IPv4 CIDR list: %w", err)
		return
	}
	if err = cidr.LoadURL(ranger, "https://www.cloudflare.com/ips-v6"); err != nil {
		err = fmt.Errorf("failed to load Cloudflare IPv6 CIDR list: %w", err)
		return
	}
	if err = cidr.LoadASN(ranger, 13335); err != nil {
		err = fmt.Errorf("failed to load Cloudflare ASN CIDR list: %w", err)
		return
	}
	return
}
