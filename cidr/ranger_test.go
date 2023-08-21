package cidr

import (
	"errors"
	"net"
	"testing"

	"github.com/yl2chen/cidranger"
)

func TestMatchingCloudflareIPs(t *testing.T) {
	ranger := cidranger.NewPCTrieRanger()
	err := LoadURL(ranger, "https://www.cloudflare.com/ips-v4")
	if err != nil {
		t.Fatal(err)
	}
	err = LoadURL(ranger, "https://www.cloudflare.com/ips-v6")
	if err != nil {
		t.Fatal(err)
	}
	err = LoadASN(ranger, 13335)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("104.28.157.104")
	contains, err := ranger.Contains(ip)
	if err != nil {
		t.Fatal(err)
	}
	if !contains {
		t.Errorf("IP %s not found in ranger", ip.String())
	}
	ip = net.ParseIP("2405:8100::")
	contains, err = ranger.Contains(ip)
	if err != nil {
		t.Fatal(err)
	}
	if !contains {
		t.Errorf("IP %s not found in ranger", ip.String())
	}
	ip = net.ParseIP("invalid")
	if ip != nil {
		t.Errorf("net.ParseIP should return nil for invalid ip")
	}
	contains, err = ranger.Contains(ip)
	if !errors.Is(err, cidranger.ErrInvalidNetworkNumberInput) {
		t.Errorf("nil IP should returns cidranger.ErrInvalidNetworkNumberInput")
	}
	if contains {
		t.Errorf("nil IP should never be in ranger")
	}
}
