/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package httpserver

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	firstCertFileName   string = "firstCert.crt"
	firstKeyFileName    string = "firstKey.key"
	firstCACertFileName string = "firstCACert.crt"
	invalidPath         string = "invalid"
)
const firstCertificate string = `-----BEGIN CERTIFICATE-----
MIIDAjCCAeqgAwIBAgIUAbsAmO7kx6m5NgjlMLTvdHNqZtAwDQYJKoZIhvcNAQEL
BQAwKjEPMA0GA1UECgwGUmF0aWZ5MRcwFQYDVQQDDA5SYXRpZnkgUm9vdCBDQTAe
Fw0yMzA1MTgxOTQ5MzVaFw0yNDA1MTcxOTQ5MzVaMCMxITAfBgNVBAMMGHJhdGlm
eS5nYXRla2VlcGVyLXN5c3RlbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBANDh5yHzotQdPEZtI6S6Grq/85h29Q03iUbH5Bmc8MDKwl0QqX0UY1D1Ue4f
aFNJ+odD2yHdS6t1rCjEw/xdaaqVN82/d0/qBVoIfeUUBSKmrOQcaXIOzHidO2ci
++jPCRWApCay6k32t9G4NDZi99fwgybI19KNA1tmpQEU6pPRi37vljupplBSGFme
eSFPkmbXa/ECX0BjpAfs4if+8pzgIHqWvVT0Wl3SFLhXYfCQERupv/d+DGbTlTif
lWanDmZWLSSlPxgcgjjzQICU0Kj8WW7zxTSejwYCq7L+FL4XcWUurgqSxFNj41qT
cEeDFc1iWewLWCDA7D2wGjH43vUCAwEAAaMnMCUwIwYDVR0RBBwwGoIYcmF0aWZ5
LmdhdGVrZWVwZXItc3lzdGVtMA0GCSqGSIb3DQEBCwUAA4IBAQBRffIo/nY0JfNr
4IA3AI9fHkGKmwt2/tqEUe8paL+h42MWxa7FrSBMwcqOyhD+mrPDqC4CDqVOq5YY
ymzCuCbHsJqTohioPakFl80XTi03VZgMiySrWOwLtfBKSYxVhHI7jrR4VSLipxMu
Zu5gYBGyM/LEl2Mqg4+US5IMt9DsL83J8nMweIFv8Zsckz/Y4Gm9VGOAfKb2GUan
8etfPff+KRO5Gg4Pl/kwmOU+4vDpn+1PVyPzn3CVIDplcqcpeqjdV9YDBrlz0Ge+
Qh/RHtx6eyYD5PcLjlv9DO2SslR2kWYV0cJjTrlNGzscLrKSQj3vEJIJ5NKGvcvH
kxxpbB05
-----END CERTIFICATE-----`
const firstKey string = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDQ4ech86LUHTxG
bSOkuhq6v/OYdvUNN4lGx+QZnPDAysJdEKl9FGNQ9VHuH2hTSfqHQ9sh3Uurdawo
xMP8XWmqlTfNv3dP6gVaCH3lFAUipqzkHGlyDsx4nTtnIvvozwkVgKQmsupN9rfR
uDQ2YvfX8IMmyNfSjQNbZqUBFOqT0Yt+75Y7qaZQUhhZnnkhT5Jm12vxAl9AY6QH
7OIn/vKc4CB6lr1U9Fpd0hS4V2HwkBEbqb/3fgxm05U4n5Vmpw5mVi0kpT8YHII4
80CAlNCo/Flu88U0no8GAquy/hS+F3FlLq4KksRTY+Nak3BHgxXNYlnsC1ggwOw9
sBox+N71AgMBAAECggEBAJAhYF/wAgnExoN96VtPwwPbUVWBt6NQD9wUL5Nw1Drj
bWvUBG83MzR4ofjiGRVndYQCUWEzlnQP9SQIaYdoWXIIFoJUvBobS2gNdfkscEKx
qZiY9jVqerI7I/MNk67XtNfudNXzHHOBauM97GEetw98eLK5YRp6jLdzwyVU7mvh
qjlSO0PsYWhrRU4slxNsQMPy4aOetcavJFoidCZZbAt+LBVRrLDNRUf5rX99s+s4
8yp+fGgj6NwxSoDaps6cAYWmLCYk3c7fPbeLokP3Qnmi5cn74qkJ5Y39XdnSSyep
sQl7vDTl67DC4ujc2aVGIB3iasiq7qCF98phesdaQEECgYEA928v0ii4csJN/gqE
d6Bks755BZPpQz//0aiSVJ8MC7zng8BDQ407dHgHWofNxLsdHNkW9FpGL+R/wLSu
fj+1r7kX6iOwWjsJbAETF+hJfWc63Vo/dyeQo+azO1EPtTLlcrpum6rR3HO7fvh2
sTdPtsxdsE308fOqK4P46qRqs1ECgYEA2B0PttCaF6WP8z1Dm5e2ea92zqBwvaJ3
oTRRucKu2nXqRPj5GK2yzmWl1NGCaS8O9FqRK9OQFuK5PSjmN6gXHI6kH3BiOhHw
AG+ENlef6pV+E2KqPF8xjqqEUfKN2hEe2FRBfduFam0AIppUB5Y2Ebl0EagQXk9v
3i2YsyyWIGUCgYEAyXHwUP1uDaA7txQA/RPMaLot9WiShHnaYGsJl3NVb0kAg7dI
C/sz6ILAGehukjh0X0Qu+Al3Ew7JI672UTq1RLdAzRL5RLzD0vadAN3Q1xPwTL5o
5S2FCKuOSECatT8Wpu05l+reqMhgYeMPXwBVGdIQhLUzMrjaVks/oGjzpcECgYBt
P7Oz7RwYnB97DRtiSn16YlMi/URA+SKUoYg26c3OrhExsNLrwNNFN2lvfkH4vktH
B4mfqCGNECwoWMaYmCamzwz0v7FIPc0fy0AA4Kb8xXmofxYj0tOQlW6ypnVDKah4
H4/D+fcl59hLpcyY0TygFSoxys4LfwjEPjSVTxLNaQKBgQCnXKDWjqtgDwmvceQC
DH9dxDSdp/Jrz5GELXJuFzepxtGJS51CpPBV+2YOSyaSzEc9q6Usd4mSO6DCb2rM
A5p2U+ZMyVpdVxM+n2t8UxbqU8DK5Cko+6wR3q/HUXXNOtGYUrSQhQmW4y8ySyE6
7PGdPM31LcIuIjfPTG15FbNBTg==
-----END PRIVATE KEY-----
`
const firstCACert string = `-----BEGIN CERTIFICATE-----
MIIDNTCCAh2gAwIBAgIUODI+rSGQO2RuEyMftSqojjxcaRQwDQYJKoZIhvcNAQEL
BQAwKjEPMA0GA1UECgwGUmF0aWZ5MRcwFQYDVQQDDA5SYXRpZnkgUm9vdCBDQTAe
Fw0yMzA1MTgxOTQ5MzVaFw0yMzA1MTkxOTQ5MzVaMCoxDzANBgNVBAoMBlJhdGlm
eTEXMBUGA1UEAwwOUmF0aWZ5IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDO43Y+WkYsH1jKoHtzdQMii2hdrXEzltXCLrM/P1OhERZyFSlZ
QubAwzNG41gT4/cBCRTafC45hw3aTKSCY7tphgGn6qXOelMLKu9yf5I/awukylHQ
F6+H+T40tWlRLT+bXFZtByIacZmoGoWzbZRmGBKoParNZCH3vfNvb7jYM4Ehb+JA
vPEKvz0Iu7l9jh0qgS6v9wx0GBz7vDFhTQHoVFXRcY9Vb9FdnNHEx+Lc7UoW0/kJ
LKTYqLsYJXZRqfmnAocpqxjaDODBzs9+k6ulrrqoZjyZmkbVbaFSLLvIVAeHzuwL
0gQbz8OEIP+uqH+7VhGb6vbKknAMwja+EbHDAgMBAAGjUzBRMB0GA1UdDgQWBBSD
TaR4b0ju72jRo1RMffIHt3fIcDAfBgNVHSMEGDAWgBSDTaR4b0ju72jRo1RMffIH
t3fIcDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBGVtPpetE8
Fe9aAN/ZLmaIj14FfvAy7LOSv1AIDNFgNLTbo25z+IH7cQf1Ws967BqlaW79gg8y
k9en7wfLBy3G/teU00bOy2eYtPIsVwLgrpIbVU6VYeUg1i86/pk/tNzOiDRj06qO
Dztv/HJIGGcLwj1T2yiiFnizgRlwmUSVi1BDu4c34A0P9OGoZPSZ97/hhHauK81o
WqlYtBTNTFx4eisM277wPKV8iHNGqULVGtADGmU0WWsWPDmHytmBaE5tF/NifRrF
1oSTxUCtw319hyHUFX5xHq2REEN+tbxTUbVsgXVTrZmnuSxN2WFAfvuPVKxQ9RD9
ve39ZodlqIAz
-----END CERTIFICATE-----
`
const secondCertificate string = `-----BEGIN CERTIFICATE-----
MIIDAjCCAeqgAwIBAgIUKM/3jH+txmBUCQAOTc93FjzJUP0wDQYJKoZIhvcNAQEL
BQAwKjEPMA0GA1UECgwGUmF0aWZ5MRcwFQYDVQQDDA5SYXRpZnkgUm9vdCBDQTAe
Fw0yMzA1MjMyMTUzMDNaFw0yNDA1MjIyMTUzMDNaMCMxITAfBgNVBAMMGHJhdGlm
eS5nYXRla2VlcGVyLXN5c3RlbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALcOqIaafGjT4aRc4OLQCK+2pSEHgZSKdv/pRBDLT6+Tbe8vrK9eLRhuoEIw
k2QPeO7gQnvT+R8zlqOsS0l8echaXjrZypF8D2FACgn2nUotJFMMJvV552vKhq01
MxkD0nlhQE12TOWtR/fNavyf+GcyQW2rM72Nwj4RfdHQ56wpN2Q9WRRITWXpqy6M
RWnaVhLA9tRtSk0SRwPIk5xrLNDlVRQiw8GnAL7lK4d3n+dDdFoKHyn61pGVauav
Lf7Sd1yUoSqplEGWjA3R/T8j3sKQjOL/SeJqXI0vsniRTfIFMmlFhoTIxROVCIa4
AVDCLdQaH+9wwp29NyjqJZ0ajFsCAwEAAaMnMCUwIwYDVR0RBBwwGoIYcmF0aWZ5
LmdhdGVrZWVwZXItc3lzdGVtMA0GCSqGSIb3DQEBCwUAA4IBAQDDx3Z9Z5kwSa24
3AJZpgNIRsrnoqumqPnYt555U8oZAJKl175tHlDbJAFaRXK4cq1Ua2Q+h0ytzulo
kTi+B45PJjSdi4P62SDxJoqNaiqFoKUA98z32os/FTcyJoXDC7y7DoVpqjJkuSjH
I130FBsc+IBUeHqjSbPRoaNXOYOA36YoMtV2wJ2uPmG1wLbfyk8vqWUv4u30g7z1
36bQN1yigqNZEO0gM0pOBDodW1OhyNE83d3UHdmCcx3pejbWNWbAEbnuMluGqNLx
CGq38sYWjgy1eHctMF/MpMcCK3Nm64YYvmIwBa0wl7EJArZJLWMGpgB4MC8fwqam
+4RirFh7
-----END CERTIFICATE-----
`
const secondKey string = `-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQC3DqiGmnxo0+Gk
XODi0AivtqUhB4GUinb/6UQQy0+vk23vL6yvXi0YbqBCMJNkD3ju4EJ70/kfM5aj
rEtJfHnIWl462cqRfA9hQAoJ9p1KLSRTDCb1eedryoatNTMZA9J5YUBNdkzlrUf3
zWr8n/hnMkFtqzO9jcI+EX3R0OesKTdkPVkUSE1l6asujEVp2lYSwPbUbUpNEkcD
yJOcayzQ5VUUIsPBpwC+5SuHd5/nQ3RaCh8p+taRlWrmry3+0ndclKEqqZRBlowN
0f0/I97CkIzi/0nialyNL7J4kU3yBTJpRYaEyMUTlQiGuAFQwi3UGh/vcMKdvTco
6iWdGoxbAgMBAAECggEBAKwQMiX7Vc8uwZw91QA8rL2E/yfRp2IY2IvpFZp3kBon
iKDXfgiEi/y4FxjAEfpudKyLzNIZx8MlOYX07/tN7iZ9kq7cggRHySkPCaCd1vCf
B9KrzH7WK8ls3zQ1mib8Kbz/xXJKLTOBsfDhe5ujPdi6KzfLQWH9ukOfK1Wpd+mg
aMAt2txGkQYgFFX+m00zAxCXPs9gqgsiQvsE3HSP8PSRnOaeYIz2me0y7UWkn+Rq
jbVvtbb1VDG6A2xe3bpFWzJuybHuE13nq7zK8MwLDaYSQL15JcQhnsBXl5SnHHJJ
LvRFXxLhCBpcMO2LfnlsGr2aMqbHvzgcNcLKjB9hc5ECgYEA46JVBcYNKAPhPbN/
xjFQ4I/gmzyVPE/D5iGTnSwc2XEh5/f5S3BI7WzhSA0j0MtOo6LFC5x8JwYKCcno
geUM9GH4sI8UAmkZbquGcRU1yPGTj9LM4uBqvNL4nrSuiS+eY71MEU9a5Fw5JGYa
fdNLw7SkgluprJ9o6fNc/YxbzgMCgYEAzd5MGe4uUv9+r8o4g4KqmJmgw7FYkw7r
1hEp5eN9bvQvQRMONzhoQfDSC+DARtdTcir5JUMJH1CBsh1+alW+QgM3P8Bklqdq
yx9iYHyUqqnNx5mv46NtlhYObxy+9CVjuyVjZT29hfkl2BOlw0TmaGuUv+MvQj6p
wNKoxJFvRMkCgYEAmcwY89CvHOUaLqzzXH3/benn0BqrndcqvXbcHCosx8EHLoo9
NfoEW93fi+XM2Ao09JxJ06GDxH3xFFIFtJWEHi1/cBMLauGFnF9pc0foUf7eOyMq
6PLFSxSjg98BuZChzDOejGd4OqgQt4YAyhiTrQOEzsqNpiMCKGcT4f8OG+8CgYEA
sSnf1eTaasTC8mcVkV9OjnqPFjm1nwCVRiiJJPRMCsMLM3ZBopXhavXi3SPydERz
5GlE9aMl45P1uSGWm83kKIz569wW9GtpBRqiH6S2j9QHagFBk6Yd9a5Ph6F2V0ch
93jqe8LRKc1KmxP1cAEIQ85pOWU6U0j37x+a62a5GbkCgYEA4QPZpUBU+tiLeQRn
8Jh6G6OELoMHf1Ik6dtDFGM2Cnjmu5iUyRDSsyEQEvRD81RgNbaeIbvagpCCafLJ
IaJp+XVCACjQmmJxJzMPXPjGIQnmk6VrDXttJKQA49DAEZ/aboXGSxjNZiNW3orB
US+cjMyfbSZlnfuxmH5YXqX10co=
-----END PRIVATE KEY-----
`
const secondCACert string = `-----BEGIN CERTIFICATE-----
MIIDNTCCAh2gAwIBAgIUdZS8ouQu+djZ+H+LqqOCVkw89N8wDQYJKoZIhvcNAQEL
BQAwKjEPMA0GA1UECgwGUmF0aWZ5MRcwFQYDVQQDDA5SYXRpZnkgUm9vdCBDQTAe
Fw0yMzA1MjMyMTUzMDNaFw0yMzA1MjQyMTUzMDNaMCoxDzANBgNVBAoMBlJhdGlm
eTEXMBUGA1UEAwwOUmF0aWZ5IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDaMktJqu7h89TLP/JGNtU0f1zCxQEdiVJZQpDxHHVbwp7fW+j7
MF68N7AGIVgMXuAsu/ewtA0Y6M+zr8ZJ3sBxWWX//QHoNqOIsGDS8Jx0jsG8448q
0wnkrwWMMiz8Vw182byPKOPlrnrdZ65KjuXXBtWR0LOaZXqQ1e7UA+AloBY8OTk7
T10ZuyolB/PL8nNIjCesVzTvzHRdR+WC446XeXED68IpV/7uInzzpV/+z1k3foR5
/wFK/p5Qt5SGcQCacIWBWFTXNLOggZgEpQBZbdO0jQF0fqjAEfksjzgngLALQ+GF
Zp1N2DrmC6RXirvCtnK6Ctto6hgaetWFz7mFAgMBAAGjUzBRMB0GA1UdDgQWBBTP
fzcZabuyIPwAZxgqVQyhmt2J8jAfBgNVHSMEGDAWgBTPfzcZabuyIPwAZxgqVQyh
mt2J8jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBLB87eJAld
zp8is33YCyu1iQcfXhzMCI/vQVwieV7YPQPYSrn+QQete02n8jzibd2QhPrQbZa5
mYejaR7fVlJ8KWkhOZAr9nKor7oC3rBywQ9lQhKIUOJr4REPcr11j+iZACcHq/xW
CQ6putzEi4jjDcRQ3bJEEGTcYSQt8KYLzuCYUyS0kjU5Qu9i6Obv4ZhT5/JBIYr9
+cyT75CQ6D1qyQB0zjtJ1oPWBux5Poix46TGRXXeeR50qEb+bIdNa24aJ+F32iXV
A2lm1FHtdZBdx6x23Oz6FY6YM4jk6CAVwQCkfOsolEVtQqC7IytHrKc+EMVYTjdx
WbAZC9hFRlJ1
-----END CERTIFICATE-----
`

func TestNewTLSCertWatcher_Expected(t *testing.T) {
	// setup temp dir with test certs/key
	tmpDir, err := os.MkdirTemp("", "test-certs")
	if err != nil {
		t.Fatalf("temp dir creation failed %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certFileName := filepath.Join(tmpDir, firstCertFileName)
	if err = os.WriteFile(certFileName, []byte(firstCertificate), 0600); err != nil {
		t.Fatalf("cert file creation failed %v", err)
	}
	keyFileName := filepath.Join(tmpDir, firstKeyFileName)
	if err = os.WriteFile(keyFileName, []byte(firstKey), 0600); err != nil {
		t.Fatalf("cert key creation failed %v", err)
	}
	caFileName := filepath.Join(tmpDir, firstCACertFileName)
	if err = os.WriteFile(caFileName, []byte(firstCACert), 0600); err != nil {
		t.Fatalf("ca cert file creation failed %v", err)
	}
	// initialize cert watcher with empty paths
	var cw *TLSCertWatcher
	_, err = NewTLSCertWatcher("", "", nil)
	if err == nil {
		t.Errorf("Expected error, got %v", err)
	}
	// initialize cert watcher with valid paths
	cw, err = NewTLSCertWatcher(certFileName, keyFileName, []string{caFileName})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// check if cert watcher is initialized correctly
	if cw.ratifyServerCertPath != certFileName {
		t.Errorf("Expected %s, got %s", certFileName, cw.ratifyServerCertPath)
	}
	if cw.ratifyServerKeyPath != keyFileName {
		t.Errorf("Expected %s, got %s", keyFileName, cw.ratifyServerKeyPath)
	}
	if len(cw.clientCACertPaths) != 1 || cw.clientCACertPaths[0] != caFileName {
		t.Errorf("Expected %s, got %v", caFileName, cw.clientCACertPaths)
	}
	if cw.ratifyServerCert == nil {
		t.Errorf("Expected ratifyServerCert to be set")
	}
	if cw.clientCACert == nil {
		t.Errorf("Expected clientCACert to be set")
	}
	if cw.watcher == nil {
		t.Errorf("Expected watcher to be set")
	}
}

func TestReadCertificates_Expected(t *testing.T) {
	// setup temp dir with test certs/key
	tmpDir, err := os.MkdirTemp("", "test-certs")
	if err != nil {
		t.Fatalf("temp dir creation failed %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certFileName := filepath.Join(tmpDir, firstCertFileName)
	if err = os.WriteFile(certFileName, []byte(firstCertificate), 0600); err != nil {
		t.Fatalf("cert file creation failed %v", err)
	}
	keyFileName := filepath.Join(tmpDir, firstKeyFileName)
	if err = os.WriteFile(keyFileName, []byte(firstKey), 0600); err != nil {
		t.Fatalf("cert key creation failed %v", err)
	}
	caFileName := filepath.Join(tmpDir, firstCACertFileName)
	if err = os.WriteFile(caFileName, []byte(firstCACert), 0600); err != nil {
		t.Fatalf("ca cert file creation failed %v", err)
	}

	// test with empty cert/key paths
	cw := &TLSCertWatcher{}
	if err := cw.ReadCertificates(); err == nil {
		t.Errorf("Expected error, got %v", err)
	}

	// test with invalid ca cert path
	cw.ratifyServerCertPath = invalidPath
	cw.clientCACertPaths = []string{invalidPath}
	cw.ratifyServerKeyPath = invalidPath
	if err := cw.ReadCertificates(); err == nil {
		t.Errorf("Expected error, got %v", err)
	}

	// test with invalid cert/key paths
	cw.clientCACertPaths = []string{caFileName}
	if err := cw.ReadCertificates(); err == nil {
		t.Errorf("Expected error, got %v", err)
	}

	// test with valid cert/key paths
	cw.ratifyServerCertPath = certFileName
	cw.ratifyServerKeyPath = keyFileName
	if err := cw.ReadCertificates(); err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestCertRotation(t *testing.T) {
	// setup temp dir with test certs/key
	tmpDir, err := os.MkdirTemp("", "test-certs")
	if err != nil {
		t.Fatalf("temp dir creation failed %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certFileName := filepath.Join(tmpDir, firstCertFileName)
	if err = os.WriteFile(certFileName, []byte(firstCertificate), 0600); err != nil {
		t.Fatalf("cert file creation failed %v", err)
	}
	keyFileName := filepath.Join(tmpDir, firstKeyFileName)
	if err = os.WriteFile(keyFileName, []byte(firstKey), 0600); err != nil {
		t.Fatalf("cert key creation failed %v", err)
	}
	caFileName := filepath.Join(tmpDir, firstCACertFileName)
	if err = os.WriteFile(caFileName, []byte(firstCACert), 0600); err != nil {
		t.Fatalf("ca cert file creation failed %v", err)
	}

	// set up new cert watcher
	var cw *TLSCertWatcher
	cw, err = NewTLSCertWatcher(certFileName, keyFileName, []string{caFileName})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// start cert watcher
	if err = cw.Start(); err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	defer cw.Stop()

	// load actual cert bundle and ca cert
	actualCertBundle, err := tls.LoadX509KeyPair(certFileName, keyFileName)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	actualCaKey := x509.NewCertPool()
	actualCaKey.AppendCertsFromPEM([]byte(firstCACert))

	// check if certs match
	if !bytes.Equal(actualCertBundle.Certificate[0], cw.ratifyServerCert.Certificate[0]) {
		t.Errorf("Expected ratify certs to match")
	}
	if !actualCaKey.Equal(cw.clientCACert) {
		t.Errorf("Expected client CA certs to match")
	}

	// update cert/key files for rotation
	if err = os.WriteFile(certFileName, []byte(secondCertificate), 0600); err != nil {
		t.Fatalf("second cert file creation failed %v", err)
	}
	if err = os.WriteFile(keyFileName, []byte(secondKey), 0600); err != nil {
		t.Fatalf("cert key creation failed %v", err)
	}
	if err = os.WriteFile(caFileName, []byte(secondCACert), 0600); err != nil {
		t.Fatalf("second ca cert file creation failed %v", err)
	}

	// wait for cert rotation (watcher is not instant)
	time.Sleep(1 * time.Second)

	// reload actual cert bundle and ca cert
	actualCertBundle, err = tls.LoadX509KeyPair(certFileName, keyFileName)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	actualCaKey = x509.NewCertPool()
	actualCaKey.AppendCertsFromPEM([]byte(secondCACert))

	// check if updated certs match
	if !bytes.Equal(actualCertBundle.Certificate[0], cw.ratifyServerCert.Certificate[0]) {
		t.Errorf("Expected ratify certs to match")
	}
	if !actualCaKey.Equal(cw.clientCACert) {
		t.Errorf("Expected client CA certs to match")
	}
}

func TestIsWrite_Expected(t *testing.T) {
	actual := fsnotify.Event{Op: fsnotify.Write}
	if !isWrite(actual) {
		t.Errorf("Expected true, got false")
	}
}

func TestIsCreate_Expected(t *testing.T) {
	actual := fsnotify.Event{Op: fsnotify.Create}
	if !isCreate(actual) {
		t.Errorf("Expected true, got false")
	}
}

func TestIsRemove_Expected(t *testing.T) {
	actual := fsnotify.Event{Op: fsnotify.Remove}
	if !isRemove(actual) {
		t.Errorf("Expected true, got false")
	}
}
