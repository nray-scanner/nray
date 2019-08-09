package targetgeneration

import (
	"fmt"
	"net"
	"sort"
	"testing"

	"github.com/apparentlymart/go-cidr/cidr"
)

func TestReceiveTargets(t *testing.T) {
	g := standardTGBackend{
		maxHosts:    192,
		maxTCPPorts: 50,
		maxUDPPorts: 50,
	}

	g.rawTargets = []string{"192.168.0.0/24"}
	g.tcpPorts = []uint16{21}
	ips := make([]string, 0)

	_, ipnet, _ := net.ParseCIDR(g.rawTargets[0])
	targetChan := g.receiveTargets()
	for targets := range targetChan {
		for _, target := range targets.RemoteHosts {
			if !ipnet.Contains(net.ParseIP(target)) {
				t.Fail()
			}
			ips = append(ips, target)
		}
	}

	if cidr.AddressCount(ipnet) != uint64(len(ips)) {
		t.Fail()
	}

	// A subnet should be included in a bigger net
	g.rawTargets = []string{"192.168.0.0/25"}

	ips = make([]string, 0)
	targetChan = g.receiveTargets()
	for targets := range targetChan {
		for _, target := range targets.RemoteHosts {
			if !ipnet.Contains(net.ParseIP(target)) {
				t.Fail()
			}
			ips = append(ips, target)
		}
	}
	_, blacklistnet, _ := net.ParseCIDR("192.168.0.0/25")

	if cidr.AddressCount(ipnet)-cidr.AddressCount(blacklistnet) != uint64(len(ips)) {
		t.Fail()
	}

	g.rawTargets = []string{"10.10.43.0/12"}
	g.tcpPorts = []uint16{21, 80, 443}
	_, ipnet, _ = net.ParseCIDR("10.10.43.0/12")
	ips = make([]string, 0)
	targetChan = g.receiveTargets()
	for targets := range targetChan {
		for _, target := range targets.RemoteHosts {
			if !ipnet.Contains(net.ParseIP(target)) {
				t.Fail()
			}
			ips = append(ips, target)
		}
	}
	if cidr.AddressCount(ipnet) != uint64(len(ips)) {
		t.Fail()
	}

	g.rawTargets = []string{"172.24.12.0/28"}
	g.tcpPorts = []uint16{8080}
	_, ipnet, _ = net.ParseCIDR("172.24.12.0/28")
	ips = make([]string, 0)
	targetChan = g.receiveTargets()
	for targets := range targetChan {
		for _, target := range targets.RemoteHosts {
			if target == "172.24.12.25" {
				t.Fail()
			}
			if !ipnet.Contains(net.ParseIP(target)) {
				t.Fail()
			}
			ips = append(ips, target)
		}

	}
	if cidr.AddressCount(ipnet) != uint64(len(ips)) {
		t.Fail()
	}

	g.rawTargets = []string{"127.0.0.1", "scanme.nmap.org", "honeypot.local", "www.google.com", "https://scanme.nmap.org:443/"}
	g.tcpPorts = []uint16{80, 443, 25}
	g.blacklist = NewBlacklist()
	g.blacklist.AddToBlacklist("honeypot.local")
	targetChan = g.receiveTargets()
	target := <-targetChan

	if target.RemoteHosts[0] != "127.0.0.1" || target.RemoteHosts[1] != "scanme.nmap.org" || target.RemoteHosts[2] != "www.google.com" {
		t.Fail()
	}
	if len(target.RemoteHosts) != 3 {
		t.Fail()
	}
	for _, port := range target.TCPPorts {
		if !(port == 80 || port == 443 || port == 25) {
			t.Fail()
		}
	}

}

func TestParsePorts(t *testing.T) {
	var results []uint16
	var expected []uint16

	// 22
	expected = []uint16{22}
	results = ParsePorts([]string{"22"}, "tcp")
	if len(results) != len(expected) {
		t.Fail()
	}
	for pos := range results {
		if results[pos] != expected[pos] {
			t.Fail()
		}
	}

	// 80,443
	expected = []uint16{80, 443}
	results = ParsePorts([]string{"80", "443"}, "tcp")
	sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })
	if len(results) != len(expected) {
		t.Fail()
	}
	for pos := range results {
		if results[pos] != expected[pos] {
			t.Fail()
		}
	}

	// "8080-8888"
	expected = []uint16{8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088}
	results = ParsePorts([]string{"8080-8088"}, "tcp")
	sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })
	if len(results) != len(expected) {
		t.Fail()
	}
	for pos := range results {
		if results[pos] != expected[pos] {
			t.Fail()
		}
	}

	// "30-22"
	expected = []uint16{22, 23, 24, 25, 26, 27, 28, 29, 30}
	results = ParsePorts([]string{"30-22"}, "tcp")
	sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })
	if len(results) != len(expected) {
		t.Fail()
	}
	for pos := range results {
		if results[pos] != expected[pos] {
			t.Fail()
		}
	}

	// "top10"
	expected = []uint16{21, 22, 23, 25, 80, 110, 139, 443, 445, 3389}
	results = ParsePorts([]string{"top10"}, "tcp")
	sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })
	if len(results) != len(expected) {
		t.Fail()
	}
	for pos := range results {
		if results[pos] != expected[pos] {
			t.Fail()
		}
	}

	// misc tests
	expected = []uint16{21, 22, 23, 25, 80, 110, 139, 443, 445, 3389}
	results = ParsePorts([]string{"top10", "top5", "139", "443", "21-23"}, "tcp")
	sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })
	if len(results) != len(expected) {
		t.Fail()
	}
	for pos := range results {
		if results[pos] != expected[pos] {
			t.Fail()
		}
	}

	// errorchan
	expected = []uint16{21, 22, 23, 25, 80, 110, 139, 443, 445, 3389}
	results = ParsePorts([]string{"top10", "top5", "139", "443", "21-23", "lorem ipsum", "www.google.com"}, "tcp")
	sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })
	if len(results) != len(expected) {
		t.Fail()
	}
	for pos := range results {
		if results[pos] != expected[pos] {
			t.Fail()
		}
	}
}

func TestMayBeFQDN(t *testing.T) {
	// FQDN
	fqdns := []string{"www.google.com", "127.0.0.1", "localhost", "some.long.domain.local"}
	for _, element := range fqdns {
		if !mayBeFQDN(element) {
			fmt.Printf("%s should be recognized as FQDN\n", element)
			t.Fail()
		}
	}

	// No FQDN
	notfqdns := []string{"https://www.google.com/", "localhost:8080", "http://localhost:8100"}
	for _, element := range notfqdns {
		if mayBeFQDN(element) {
			fmt.Printf("%s should not be recognized as FQDN\n", element)
			t.Fail()
		}
	}
}
