package hostkeydns

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

// DNSSecResolvers exposes configuration options for resolving hostnames using
// DNSSEC.
type DNSSecResolvers struct {
	Servers []string
	Port    string
	Net     string
}

func (d *DNSSecResolvers) fqdnHostname(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func (d *DNSSecResolvers) hostname(nameAndPort string) string {
	if strings.Contains(nameAndPort, ":") {
		return strings.Split(nameAndPort, ":")[0]
	}

	return nameAndPort
}

func (d *DNSSecResolvers) check(host string, remote net.Addr, key ssh.PublicKey) error {
	config := dns.ClientConfig{
		Servers: d.Servers,
		Port:    d.Port,
	}
	c := dns.Client{
		Net: d.Net,
	}
	m := &dns.Msg{}
	m.SetEdns0(4096, true)

	m.SetQuestion(d.fqdnHostname(d.hostname(host)), dns.TypeSSHFP)
	m.RecursionDesired = true

	var resp dns.Msg
	for _, s := range config.Servers {
		r, _, err := c.Exchange(m, s+":"+config.Port)
		if err != nil {
			continue
		}
		if r.Rcode == dns.RcodeSuccess {
			resp = *r
			break
		}
	}

	keyBytes := key.Marshal()
	for _, a := range resp.Answer {
		if fp, ok := a.(*dns.SSHFP); ok {
			fingerprint, err := hex.DecodeString(fp.FingerPrint)
			if err != nil {
				return err
			}

			// If we match, return nil marking success
			switch fp.Type {
			case 1:
				hash := sha1.Sum(keyBytes)
				if bytes.Equal(fingerprint, hash[:]) {
					return nil
				}
			case 2:
				hash := sha256.Sum256(keyBytes)
				if bytes.Equal(fingerprint, hash[:]) {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("no matching SSHFP record found for %q", host)
}

// CheckDNSSecHostKey checks a hostkey against a DNSSEC SSHFP records.
func CheckDNSSecHostKey(hk DNSSecResolvers) ssh.HostKeyCallback {
	return hk.check
}

// CheckDNSSecHostKeyEZ checks a hostkey against a DNSSEC SSHFP records using
// preconfigured name servers (Quad9: https://www.quad9.net/).
func CheckDNSSecHostKeyEZ() ssh.HostKeyCallback {
	hk := &DNSSecResolvers{
		Servers: []string{
			"9.9.9.9",
			"149.112.112.112",
		},
		Port: "53",
		Net:  "udp",
	}
	return hk.check
}
