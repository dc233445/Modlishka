/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package plugin

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/drk1wi/Modlishka/config"
	"github.com/drk1wi/Modlishka/log"
)

// Paste your CA certificate and key in the following format
// Ref: https://github.com/drk1wi/Modlishka/wiki/Quickstart-tutorial

const CA_CERT = `-----BEGIN CERTIFICATE-----
MIIDljCCAn4CCQDjkF4rf2kavDANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMC
dVMxCzAJBgNVBAgMAk5BMQswCQYDVQQHDAJOQTELMAkGA1UECgwCTkExCzAJBgNV
BAsMAk5BMR4wHAYDVQQDDBVsb29wYmFjay5tb2RsaXNoa2EuaW8xKTAnBgkqhkiG
9w0BCQEWGmZyZWVzbW9rZWFuZGNvZGVAZ21haWwuY29tMB4XDTIwMTIzMTIyNDAy
M1oXDTIzMTAyMTIyNDAyM1owgYwxCzAJBgNVBAYTAnVTMQswCQYDVQQIDAJOQTEL
MAkGA1UEBwwCTkExCzAJBgNVBAoMAk5BMQswCQYDVQQLDAJOQTEeMBwGA1UEAwwV
bG9vcGJhY2subW9kbGlzaGthLmlvMSkwJwYJKoZIhvcNAQkBFhpmcmVlc21va2Vh
bmRjb2RlQGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANeCqqAtwnLVpOzTPAxM8YYq7t1VZai2jnBH61imrWaWy1SqjbGgeDUKbfW9QImy
h2QvjZAykHykl0Xv7VA5XIoCp+f10SIWtcHoUUnfD9WCZU4IL159ZdKpRyRgA36d
7qxolZK4OOzipSBu8JDa0UogjfkQZSiUljwTKTKI2KHCGjObDnipKa7auW/YGh3W
I9wJQGy0U8AIikjGcU4yAVjUJfP0H2BvqjTgXgeugGRXpVZzYDrrN9K/HPn2BbJr
nuxgm+/4a3MAp8l+s1FnmmyuILMM4VZ5oqHpHgjdJ1euqGXt/8lj0KoX73YGXvph
IsrBeHy/C1it9J57jTntyicCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAAGbPBQf9
203aiKXAphHb/FWGXDl1+jhviE5Zpe+AAa3vp1qQDbLrKezhQbwQ/bGeVFJoL+rl
NoWYk9RjQCvX5x8AkOh/L56PI3bPgvMZHUu7yMiqEvj+whjMNe+6THHz1wYSzSuv
sRU+IWyC1fxuhRbKTZEfz2WGbdOtdEIc+DpjCYFWOlPDUJzYFbE/bwIQKXWTG3wg
t3N7rfuGpSq/TlBLDudWBck45DTMbRUKTYKwXyiglObmJmTyS1qLE7BQNbb1zXOc
UTyCWZSd7wQil17A7PR3UugxjU4ESVsT5Ba+xvApWAKQqayKksg2x4m/kX87gPo8
fD0jcgLrtk75Sw==
-----END CERTIFICATE-----`

const CA_CERT_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA14KqoC3CctWk7NM8DEzxhiru3VVlqLaOcEfrWKatZpbLVKqN
saB4NQpt9b1AibKHZC+NkDKQfKSXRe/tUDlcigKn5/XRIha1wehRSd8P1YJlTggv
Xn1l0qlHJGADfp3urGiVkrg47OKlIG7wkNrRSiCN+RBlKJSWPBMpMojYocIaM5sO
eKkprtq5b9gaHdYj3AlAbLRTwAiKSMZxTjIBWNQl8/QfYG+qNOBeB66AZFelVnNg
Ous30r8c+fYFsmue7GCb7/hrcwCnyX6zUWeabK4gswzhVnmioekeCN0nV66oZe3/
yWPQqhfvdgZe+mEiysF4fL8LWK30nnuNOe3KJwIDAQABAoIBAHqAfwbgHAj0onQw
OpDvZ9cRLohH06qMYvk2GHRjAmwvSVNOQ471nX7g99JZCod7IPT1Bu4xn+oKEScj
E+2nPZABpHn5RDCxYg3gRdzM3A5MudMaWfrHIwsVSChIH5Rop9P++w7Ugx88UgrW
pQ5iI9eUG7+47xebJq7tYVylZybCyAB2MPsvE8lvfavmUIatynOD+GsG6QvTt6Jy
McfNsSAbnsEu+sm8BsiYuowWeoq3Rlk5zY3kiQUwAgRtimgmnG2UX/ctWo45+oJr
NFpHmwnWfEM8yyzj6dvUVJudtRaryPBwYpYPAMcAO9Z8W/wAX3hM0d/h5iTgJPFB
O5h/iVECgYEA/tNAcMt1lXKCemULctOPyZH52KRntUxXzW1PMEZRo7+hYQYIVa70
9oB7HTC1yYlS0Mab5yZx1CrXiC+1cLEnDRc3/7Hw+tkTz2wDNCjL4J90e1MjHILb
K1hSJsaosa5qtW0sNKYjjdbGagGF82RhjeOg7V6I3drs1DBSk0wRbB8CgYEA2IED
0gY72mF/0+0+TGwzCOjop7D+i+SD7fhH8HGTw8PJEPDuyoUWgXPtKlJZmOgFlfZH
z1ap+zYZMDIcXHqEHEQwk/i5NGt3nmXQKtYzTfwi4Ov9fQts4v/2afjb0FHpCwPa
WoY68Xt+vyBRs580TMN5Ozoc/CqDQov0nr2QYPkCgYBulwvOZ94935ZUu+l+CebL
GfkOVjtT6S/pzViioMHpiM7mppGTbfyNxjCn+G3MazZvuOIMLRkVdQpY5iueHqPO
AJei9nyYwQDh8gRp7JKeh1Ur+Gayhu/LHed5QJoRkppo5lpa9wdTFTTC6KpTeOsF
gxZiLbbEYbCKXfZYSpj9DQKBgAVoa5UCbNpOlyfPBEBab4focW9G34TVB2qZSgq6
e4tnR41xxzUtz9sZ7zGgbvZ/zSvqw+5s5sAMoOJwTf8NXGFsXp5DlzS0/n7pYiK/
yPZItwJRQrqt32FoLVqGSc9RTHXm+bxLIAvKHuddQk0vS9ojA9Mz52dxFGhEIK8a
YxHZAoGAMg7x8yv4NTJ1vkOyVASDZQtAZBPGNdd3uVw87XwZs5JG3G0nhhw7rBKM
0RkKSjEZhqWOt6vk4E27e4JIfKJYX0BeGP4WfffLexNIOqhgrwGeOEuY8/GLUi/M
KGRWDzVcxY0qFyFjf3HTJKtQ3n7aN0u2VVrfroOlz/RW0PUTizc=
-----END RSA PRIVATE KEY-----`

func init() {

	s := Property{}

	s.Name = "autocert"
	s.Version = "0.1"
	s.Description = "This plugin is used to auto generate certificate for you . Really useful for testing different configuration flags against your targets. "

	s.Flags = func() {

		if *config.C.ForceHTTP == false {
			if len(*config.C.TLSCertificate) == 0 && len(*config.C.TLSKey) == 0 {

				log.Infof("Autocert plugin: Auto-generating %s domain TLS certificate",*config.C.ProxyDomain)

				CAcert := CA_CERT
				CAkey := CA_CERT_KEY

				catls, err := tls.X509KeyPair([]byte(CAcert), []byte(CAkey))
				if err != nil {
					panic(err)
				}
				ca, err := x509.ParseCertificate(catls.Certificate[0])
				if err != nil {
					panic(err)
				}

				var n int32
				binary.Read(rand.Reader, binary.LittleEndian, &n)

				template := &x509.Certificate{
					IsCA:                  false,
					BasicConstraintsValid: true,
					SubjectKeyId:          []byte{1, 2, 3},
					SerialNumber:          big.NewInt(int64(n)),
					DNSNames:              []string{*config.C.ProxyDomain, "*." + *config.C.ProxyDomain},
					Subject: pkix.Name{
						Country:      []string{"Earth"},
						Organization: []string{"Mother Nature"},
						CommonName:   *config.C.ProxyDomain,
					},
					NotBefore: time.Now(),
					NotAfter:  time.Now().AddDate(5, 5, 5),
				}

				// generate private key
				privatekey, err := rsa.GenerateKey(rand.Reader, 2048)

				if err != nil {
					log.Errorf("Error generating key: %s", err)
				}
				var privateKey = &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
				}

				//dump
				buf := new(bytes.Buffer)
				pem.Encode(buf, privateKey)
				tlskeyStr := buf.String()
				config.C.TLSKey = &tlskeyStr
				log.Debugf("AutoCert plugin generated TlsKey:\n %s", *config.C.TLSKey)

				// generate self signed cert
				publickey := &privatekey.PublicKey

				// create a self-signed certificate. template = parent
				//var parent = template
				var parent = ca

				cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, catls.PrivateKey)

				buf = new(bytes.Buffer)
				pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

				tlscertStr := buf.String()
				config.C.TLSCertificate = &tlscertStr
				log.Debugf("AutoCert plugin generated TlsCert:\n %s", *config.C.TLSCertificate)

				//the cert is auto-generated anyway
				*config.C.TLSPool = ""

				if err != nil {
					log.Errorf("Error creating certificate: %s", err)
				}

			}
		}

	}

	// Register all the function hooks
	s.Register()
}
