package hostkeydns_test

import (
	"golang.org/x/crypto/ssh"
	"suah.dev/hostkeydns"
)

func ExampleCheckDNSSecHostKeyEZ() {
	config := &ssh.ClientConfig{
		HostKeyCallback: hostkeydns.CheckDNSSecHostKeyEZ("quad9"),
	}
	_, _ = ssh.Dial("tcp", "github.com:22", config)
}

func ExampleCheckDNSSecHostKey() {
	dnsConf := hostkeydns.DNSSecResolvers{
		Servers: []string{
			"8.8.8.8",
		},
		Port: "53",
		Net:  "tcp",
	}
	config := &ssh.ClientConfig{
		HostKeyCallback: hostkeydns.CheckDNSSecHostKey(dnsConf),
	}
	_, _ = ssh.Dial("tcp", "github.com:22", config)
}
