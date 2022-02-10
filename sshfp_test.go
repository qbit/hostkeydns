package hostkeydns

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

var hosts = map[string]bool{
	"suah.dev":      true,
	"github.com:22": false,
}
var (
	sshKey = []byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbWI0K7neB2RyQ/nFAGobmXKdYLaa4QSH08qfQ8ag3I`)
	pk     ssh.PublicKey
	wpk    ssh.PublicKey
	err    error
)

func init() {
	pk, _, _, _, _ := ssh.ParseAuthorizedKey(sshKey)
	wpk, _ = ssh.ParsePublicKey(pk.Marshal())
}

func TestDNSSECezFail(t *testing.T) {
	bad := CheckDNSSecHostKeyEZ("taters")
	err = bad("github.com:22", nil, wpk)
	if err == nil {
		t.Error("'taters' should not be valid!'")
	}

}

func TestDNSSecCustomResolver(t *testing.T) {
	for host, shouldPass := range hosts {
		hd := CheckDNSSecHostKey(DNSSecResolvers{
			Servers: []string{
				"8.8.8.8",
			},
			Port:              "53",
			Net:               "tcp",
			HostKeyAlgorithms: []string{"ssh-ed25519"},
		})
		cb := hd(host, nil, wpk)
		if cb != nil {
			if shouldPass {
				t.Error(err)
			}
		}
	}
}

func TestDNSSECez(t *testing.T) {
	for host, shouldPass := range hosts {
		ez := CheckDNSSecHostKeyEZ("quad9")
		hr := CheckDNSSecHostKeyEZ("system")
		cb := ez(host, nil, wpk)
		if cb != nil {
			if shouldPass {
				t.Errorf("EZ: %v\n", cb)
			}
		}
		cb = hr(host, nil, wpk)
		if cb != nil {
			if shouldPass {
				t.Errorf("Host resolver: %v\n", cb)
			}
		}
	}
}
