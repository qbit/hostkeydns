package hostkeydns

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

var hosts = map[string]bool{
	"suah.dev":      true,
	"github.com:22": false,
}

func TestDNSSEC(t *testing.T) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbWI0K7neB2RyQ/nFAGobmXKdYLaa4QSH08qfQ8ag3I`))
	if err != nil {
		t.Error(err)
	}
	wpk, err := ssh.ParsePublicKey(pk.Marshal())
	if err != nil {
		t.Error(err)
	}

	for host, shouldPass := range hosts {
		ez := CheckDNSSecHostKeyEZ()
		hd := CheckDNSSecHostKey(DNSSecResolvers{
			Servers: []string{
				"8.8.8.8",
			},
			Port: "53",
			Net:  "tcp",
		})

		cb := ez(host, nil, wpk)
		if cb != nil {
			if shouldPass {
				t.Error(cb)
			}
		}
		cb = hd(host, nil, wpk)
		if cb != nil {
			if shouldPass {
				t.Error(cb)
			}
		}
	}
}
