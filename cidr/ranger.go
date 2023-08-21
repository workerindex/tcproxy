package cidr

import (
	"bufio"
	"fmt"
	"net"
	"net/http"

	"github.com/PuerkitoBio/goquery"
	"github.com/yl2chen/cidranger"
)

func Add(ranger cidranger.Ranger, cidr string) (err error) {
	var ipnet *net.IPNet
	if _, ipnet, err = net.ParseCIDR(cidr); err != nil {
		return
	}
	return ranger.Insert(cidranger.NewBasicRangerEntry(*ipnet))
}

func LoadURL(ranger cidranger.Ranger, url string) (err error) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		_ = Add(ranger, scanner.Text())
	}
	return
}

func LoadASN(ranger cidranger.Ranger, asn int) (err error) {
	res, err := http.Get(fmt.Sprintf("https://bgp.he.net/AS%d", asn))
	if err != nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		err = fmt.Errorf("status code error: %d %s", res.StatusCode, res.Status)
		return
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return
	}

	doc.Find("#table_prefixes4 > tbody > tr > td:nth-child(1) > a").Each(func(i int, s *goquery.Selection) {
		_ = Add(ranger, s.Text())
	})
	doc.Find("#table_prefixes6 > tbody > tr > td:nth-child(1) > a").Each(func(i int, s *goquery.Selection) {
		_ = Add(ranger, s.Text())
	})
	return
}
