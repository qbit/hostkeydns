/*
Package hostkeydns facilitates verifying remote ssh keys using DNS and SSHFP
resource records.
*/
package hostkeydns

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

var keyAlgToSSH = map[uint8]string{
	0: "reserved",
	1: "ssh-rsa",
	2: "ssh-dsa",
	3: "ssh-ecdsa",
	4: "ssh-ed25519",
}

// DNSSecResolvers exposes configuration options for resolving hostnames using
// DNSSEC. Success will be called when a matching fingerprint/SSHFP match is
// found. Net can be one of "tcp", "tcp-tls" or "udp".
//
// If set, HostKeyAlgorithms will restrict matching to _only_ the algorithms
// listed. The format of the strings match that of OpenSSH ("ssh-ed25519" for
// example).
type DNSSecResolvers struct {
	Servers           []string
	Port              string
	Net               string
	Success           func(key ssh.PublicKey)
	HostKeyAlgorithms []string
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

func (d *DNSSecResolvers) algMatch(i uint8) bool {
	for _, a := range d.HostKeyAlgorithms {
		if a == keyAlgToSSH[i] {
			return true
		}
	}
	return false
}

func (d *DNSSecResolvers) check(host string, remote net.Addr, key ssh.PublicKey) error {
	var config *dns.ClientConfig
	var err error
	if len(d.Servers) > 0 {
		config = &dns.ClientConfig{
			Servers: d.Servers,
			Port:    d.Port,
		}
	} else {
		// TODO: windows?
		config, err = dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
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

			if len(d.HostKeyAlgorithms) > 0 {
				if !d.algMatch(fp.Algorithm) {
					continue
				}
			}

			// If we match, return nil marking success
			switch fp.Type {
			case 1:
				continue
			case 2:
				hash := sha256.Sum256(keyBytes)
				if bytes.Equal(fingerprint, hash[:]) {
					if d.Success != nil {
						d.Success(key)
					}
					return nil
				}
			}
		}
	}

	return fmt.Errorf("no matching SSHFP record found for %q", host)
}

// CheckDNSSecHostKey checks a hostkey against a DNSSEC SSHFP records.
func CheckDNSSecHostKey(dr DNSSecResolvers) ssh.HostKeyCallback {
	return dr.check
}

var ezResolvers = map[string]DNSSecResolvers{
	"quad9": {
		Servers: []string{
			"9.9.9.9",
			"149.112.112.112",
		},
		Port: "53",
		Net:  "tcp",
	},
	"google": {
		Servers: []string{
			"8.8.8.8",
			"8.8.4.4",
		},
		Port: "53",
		Net:  "tcp",
	},
	"system": {},
}

// CheckDNSSecHostKeyEZ checks a hostkey against a DNSSEC SSHFP records using
// preconfigured name servers. Options are:
//   - "quad9": https://www.quad9.net/.
//   - "google": Google's public name servers.
//   - "system": Use the system resolver (*nix only atm).
func CheckDNSSecHostKeyEZ(res string) ssh.HostKeyCallback {
	if hk, ok := ezResolvers[res]; ok {
		return hk.check
	}
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		return fmt.Errorf("invalid ez resolver: %q", res)
	}
}
