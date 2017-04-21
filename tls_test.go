package rest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	errTest     = fmt.Errorf("io")
	testSubject = pkix.Name{
		Country:            []string{"country"},
		Organization:       []string{"organization"},
		OrganizationalUnit: []string{"organization unit"},
		Locality:           []string{"locality"},
		Province:           []string{"province"},
		StreetAddress:      []string{"street address"},
		PostalCode:         []string{"postal code"},
		CommonName:         "common name",
	}
	testKey = &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: big.NewInt(1),
			E: 1,
		},
		D: big.NewInt(1),
		Primes: []*big.Int{
			big.NewInt(1),
			big.NewInt(1),
		},
		Precomputed: rsa.PrecomputedValues{
			Dp:   big.NewInt(1),
			Dq:   big.NewInt(1),
			Qinv: big.NewInt(1),
		},
	}
	testRsaPem = []byte{
		45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 82, 83, 65, 32, 80,
		82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10,
		77, 66, 115, 67, 65, 81, 65, 67, 65, 81, 69, 67, 65, 81, 69, 67,
		65, 81, 69, 67, 65, 81, 69, 67, 65, 81, 69, 67, 65, 81, 69, 67,
		65, 81, 69, 67, 65, 81, 69, 61, 10, 45, 45, 45, 45, 45, 69, 78,
		68, 32, 82, 83, 65, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69,
		89, 45, 45, 45, 45, 45, 10,
	}
)

type fakeRand struct {
	err error
}

func (f *fakeRand) Read(p []byte) (n int, err error) {
	return 0, errTest
}

type testWriter struct {
	buf   bytes.Buffer
	write func(p []byte) (n int, err error)
	close func() error
}

func (f *testWriter) Write(p []byte) (n int, err error) {
	n, err = f.write(p)
	if n > 0 {
		f.buf.Write(p)
	}
	return
}

func (f *testWriter) Close() error {
	return f.close()
}

func TestGenerateSSLCertificate(t *testing.T) {
	var tests = []struct {
		conf   CertConf
		err    string
		before func(t *testing.T)
		after  func(t *testing.T)
	}{
		{
			conf:   CertConf{Random: rand.Reader},
			err:    "could not generate RSA key,",
			before: func(t *testing.T) {},
			after:  func(t *testing.T) {},
		},
		{
			conf: CertConf{
				ValidFor:  1 * time.Hour,
				RASBits:   512,
				Subject:   testSubject,
				Random:    rand.Reader,
				HostAddrs: []string{"127.0.0.1"},
				CertOut: func() (io.WriteCloser, error) {
					return os.Create(filepath.FromSlash("test/cert.pem"))
				},
				KeyOut: func() (io.WriteCloser, error) {
					return nil, errTest
				},
			},
			err: "could not open key out,",
			before: func(t *testing.T) {
				logErr(os.Mkdir("test", 0755), t)
			},
			after: func(t *testing.T) {
				logErr(os.RemoveAll("test"), t)
			},
		},
		{
			conf: CertConf{
				ValidFor:  1 * time.Hour,
				RASBits:   512,
				Subject:   testSubject,
				Random:    rand.Reader,
				HostAddrs: []string{"127.0.0.1"},
				CertOut: func() (io.WriteCloser, error) {
					return nil, errTest
				},
				KeyOut: func() (io.WriteCloser, error) {
					return os.Create(filepath.FromSlash("test/key.pem"))
				},
			},
			err: "could not open cert out,",
			before: func(t *testing.T) {
				logErr(os.Mkdir("test", 0755), t)
			},
			after: func(t *testing.T) {
				logErr(os.RemoveAll("test"), t)
			},
		},
		{
			conf: CertConf{
				ValidFor:  1 * time.Hour,
				RASBits:   512,
				Subject:   testSubject,
				Random:    rand.Reader,
				HostAddrs: []string{"127.0.0.1", "test.com"},
				CertOut: func() (io.WriteCloser, error) {
					return os.Create(filepath.FromSlash("test/cert.pem"))
				},
				KeyOut: func() (io.WriteCloser, error) {
					return os.Create(filepath.FromSlash("test/key.pem"))
				},
			},
			err: "",
			before: func(t *testing.T) {
				logErr(os.Mkdir("test", 0755), t)
			},
			after: func(t *testing.T) {
				logErr(os.RemoveAll("test"), t)
			},
		},
	}

	for index, test := range tests {
		t.Run(fmt.Sprintf("%d. create cert", index), func(t *testing.T) {
			test.before(t)
			defer test.after(t)
			if err := errStr(GenerateTLSCertificate(test.conf)); !strings.HasPrefix(err, test.err) {
				t.Errorf("%d. exp err prefix: '%s' got: '%s'", index, test.err, err)
			}
		})
	}
}

func TestGenerateCert(t *testing.T) {
	var tests = []struct {
		conf   CertConf
		key    *rsa.PrivateKey
		serial <-chan serialRes
		exp    certRes
	}{
		{
			conf: CertConf{
				ValidFor:  1 * time.Hour,
				RASBits:   512,
				Subject:   testSubject,
				Random:    rand.Reader,
				HostAddrs: []string{"127.0.0.1"},
				CertOut: func() (io.WriteCloser, error) {
					return os.Create(filepath.FromSlash("test/cert.pem"))
				},
				KeyOut: func() (io.WriteCloser, error) {
					return os.Create(filepath.FromSlash("test/key.pem"))
				},
			},
			key: &rsa.PrivateKey{},
			serial: func() <-chan serialRes {
				res := make(chan serialRes, 1)
				res <- serialRes{err: fmt.Errorf("could not create serial number")}
				return res
			}(),
			exp: certRes{err: fmt.Errorf("could not create serial number")},
		},
	}

	for index, test := range tests {
		t.Run(fmt.Sprintf("%d. test generate cert", index), func(t *testing.T) {
			call := generateCert(test.conf, test.key, test.serial)
			got := <-call
			if !reflect.DeepEqual(test.exp, got) {
				t.Errorf("%d. exp certRes: %v got: %v", index, test.exp, got)
			}
		})
	}
}

func TestWriteKeyPem(t *testing.T) {
	var tests = []struct {
		write   func(p []byte) (n int, err error)
		close   func() error
		openErr error
		err     string
		written []byte
	}{
		{
			write: func(p []byte) (n int, err error) {
				return 0, errTest
			},
			close: func() error {
				return nil
			},
			err: "could not write key,",
		},
		{
			write: func(p []byte) (n int, err error) {
				return len(p), nil
			},
			close: func() error {
				return nil
			},
			err:     "",
			written: testRsaPem,
		},
	}

	for index, test := range tests {
		t.Run(fmt.Sprintf("%d. test write key", index), func(t *testing.T) {
			writer := &testWriter{write: test.write, close: test.close}
			conf := CertConf{
				KeyOut: func() (io.WriteCloser, error) {
					return writer, test.openErr
				},
			}

			call := writeKeyPem(conf, testKey)
			if err := errStr(<-call); !strings.HasPrefix(err, test.err) {
				t.Errorf("%d. exp err: '%s' got: '%s'", index, test.err, err)
			}

			got := writer.buf.Bytes()
			if !bytes.Equal(got, test.written) {
				t.Errorf("%d. exp written str: '%s' got: '%s", index, test.written, got)
			}
		})
	}
}

func TestWriteCertPem(t *testing.T) {
	var tests = []struct {
		conf    CertConf
		cert    <-chan certRes
		write   func(p []byte) (n int, err error)
		close   func() error
		openErr error
		err     string
		written int
	}{
		{
			conf: CertConf{
				ValidFor:  1 * time.Hour,
				RASBits:   512,
				Subject:   testSubject,
				Random:    rand.Reader,
				HostAddrs: []string{"127.0.0.1"},
			},
			cert: func() <-chan certRes {
				call := make(chan certRes, 1)
				call <- certRes{err: fmt.Errorf("could not generate cert")}
				return call
			}(),
			write: func(p []byte) (n int, err error) {
				return 0, errTest
			},
			close: func() error {
				return nil
			},
			err: "could not generate cert",
		},
		{
			conf: CertConf{
				ValidFor:  1 * time.Hour,
				RASBits:   512,
				Subject:   testSubject,
				Random:    rand.Reader,
				HostAddrs: []string{"127.0.0.1"},
			},
			cert: func() <-chan certRes {
				call := make(chan certRes, 1)
				call <- certRes{cert: func() []byte {
					cert := make([]byte, 254)
					for index := byte(0); index < 254; index++ {
						cert[index] = index
					}
					return cert
				}()}
				return call
			}(),
			write: func(p []byte) (n int, err error) {
				return 0, errTest
			},
			close: func() error {
				return nil
			},
			err: "io",
		},
		{
			conf: CertConf{
				ValidFor:  1 * time.Hour,
				RASBits:   512,
				Subject:   testSubject,
				Random:    rand.Reader,
				HostAddrs: []string{"127.0.0.1"},
			},
			cert: func() <-chan certRes {
				call := make(chan certRes, 1)
				call <- certRes{cert: func() []byte {
					cert := make([]byte, 254)
					for index := byte(0); index < 254; index++ {
						cert[index] = index
					}
					return cert
				}()}
				return call
			}(),
			write: func(p []byte) (n int, err error) {
				return len(p), nil
			},
			close: func() error {
				return nil
			},
			err:     "",
			written: 400,
		},
	}

	for index, test := range tests {
		t.Run(fmt.Sprintf("%d. test write key", index), func(t *testing.T) {
			writer := &testWriter{write: test.write, close: test.close}
			test.conf.CertOut = func() (io.WriteCloser, error) {
				return writer, test.openErr
			}

			call := writeCertPem(test.conf, test.cert)
			if err := errStr(<-call); !strings.HasPrefix(err, test.err) {
				t.Errorf("%d. exp err: '%s' got: '%s'", index, test.err, err)
			}

			written := writer.buf.Len()
			if test.written != written {
				t.Errorf("%d. exp written len: %d got: %d", index, test.written, written)
			}
		})
	}
}

func TestNewCertConf(t *testing.T) {
	var tests = []struct {
		subject pkix.Name
		addrs   []string
	}{
		{
			subject: testSubject,
			addrs:   []string{"127.0.0.1, test.com"},
		},
	}

	for index, test := range tests {
		index, test := index, test
		t.Run(fmt.Sprintf("%d. test new cert conf", index), func(t *testing.T) {
			t.Parallel()
			got := NewCertConf(test.subject, test.addrs)
			if !reflect.DeepEqual(test.subject, got.Subject) {
				t.Errorf("%d. exp subject: %+v got: %+v", index, test.subject, got.Subject)
			}
			if !reflect.DeepEqual(test.addrs, got.HostAddrs) {
				t.Errorf("%d. exp host addrs: %+v got: %+v", index, test.addrs, got.HostAddrs)
			}
		})
	}
}

func TestDefaultWriter(t *testing.T) {
	mes := []byte("this is a string")

	var tests = []struct {
		file string
		get  func() (io.WriteCloser, error)
	}{
		{
			file: "key.pem",
			get:  defaultKeyOut,
		},
		{
			file: "cert.pem",
			get:  defaultCertOut,
		},
	}

	for index, test := range tests {
		index, test := index, test
		t.Run(fmt.Sprintf("%d. test default writer %s", index, test.file), func(t *testing.T) {
			t.Parallel()
			defer func() {
				logErr(os.Remove(test.file), t)
			}()
			out, err := test.get()
			logErr(err, t)

			_, err = out.Write(mes)
			if err != nil {
				out.Close()
				t.Fatalf("unexpected error, %v", err)
			}
			out.Close()

			got, err := ioutil.ReadFile(test.file)
			logErr(err, t)

			if !bytes.Equal(mes, got) {
				t.Errorf("%d. exp file content: '%s' got: '%s'", index, mes, got)
			}

		})
	}

}

func TestCertProperties(t *testing.T) {
	writer := &testWriter{
		write: func(p []byte) (n int, err error) { return len(p), nil },
		close: func() error { return nil },
	}
	conf := CertConf{
		ValidFor:  1 * time.Hour,
		RASBits:   512,
		Subject:   testSubject,
		Random:    rand.Reader,
		HostAddrs: []string{"127.0.0.1", "test@test.com", "test.com"},
		CertOut: func() (io.WriteCloser, error) {
			return writer, nil
		},
		KeyOut: func() (io.WriteCloser, error) {
			return &testWriter{
				write: func(p []byte) (n int, err error) { return len(p), nil },
				close: func() error { return nil },
			}, nil
		},
	}
	logErr(GenerateTLSCertificate(conf), t)

	block, _ := pem.Decode(writer.buf.Bytes())
	cert, err := x509.ParseCertificate(block.Bytes)
	logErr(err, t)

	gotSubject := cert.Subject
	gotSubject.Names = nil
	if !reflect.DeepEqual(testSubject, gotSubject) {
		t.Errorf("exp subject: \n%+v\n got: \n%+v\n\n", testSubject, gotSubject)
	}

	gotIssuer := cert.Issuer
	gotIssuer.Names = nil
	if !reflect.DeepEqual(testSubject, gotIssuer) {
		t.Errorf("exp issuer: \n%+v\n got: \n%+v\n\n", testSubject, gotIssuer)
	}

	expDNSNames := []string{"test.com"}
	if !reflect.DeepEqual(expDNSNames, cert.DNSNames) {
		t.Errorf("exp DNS names: %v got: %v", expDNSNames, cert.DNSNames)
	}

	expMail := []string{"test@test.com"}
	if !reflect.DeepEqual(expMail, cert.EmailAddresses) {
		t.Errorf("exp emails: %v got: %v", expMail, cert.EmailAddresses)
	}

	expIPAddresses := []net.IP{net.IP{127, 0, 0, 1}}
	if !reflect.DeepEqual(expIPAddresses, cert.IPAddresses) {
		t.Errorf("exp IPAddresses: %v got: %v", expIPAddresses, cert.IPAddresses)
	}

	before := time.Now().Add(-1 * time.Minute)
	if !before.Before(cert.NotBefore) {
		t.Errorf("exp date: %v to be invalid", before)
	}

	after := time.Now().Add(61 * time.Minute)
	if !after.After(cert.NotAfter) {
		t.Errorf("exp date: %v to be invalid", after)
	}
}

func TestPinCert(t *testing.T) {
	defer func() {
		logErr(os.RemoveAll("test"), t)
	}()
	logErr(os.Mkdir("test", 0755), t)
	conf := CertConf{
		ValidFor:  1 * time.Hour,
		RASBits:   512,
		Subject:   testSubject,
		Random:    rand.Reader,
		HostAddrs: []string{"127.0.0.1"},
		CertOut: func() (io.WriteCloser, error) {
			return os.OpenFile("test/cert.pem", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
		},
		KeyOut: func() (io.WriteCloser, error) {
			return os.OpenFile("test/key.pem", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
		},
	}
	logErr(GenerateTLSCertificate(conf), t)

	// load cert to pin
	row, err := ioutil.ReadFile("test/cert.pem")
	logErr(err, t)
	block, _ := pem.Decode(row)
	cert, err := x509.ParseCertificate(block.Bytes)
	logErr(err, t)
	pinDer, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	logErr(err, t)

	// start test server
	go func() {
		http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("pong"))
		})
		logErr(http.ListenAndServeTLS("127.0.0.1:60601", "test/cert.pem", "test/key.pem", nil), t)
	}()

	// wait for server
	for {
		con, err := net.Dial("tcp", "127.0.0.1:60601")
		if err == nil {
			con.Close()
			break
		}
	}

	// fail handshake
	res, err := http.Get("https://127.0.0.1:60601/ping")
	if errStr(err) != "Get https://127.0.0.1:60601/ping: x509: certificate signed by unknown authority" {
		t.Errorf("exp handshake error")
	}

	// create client with pined cert
	client := &http.Client{Transport: &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			con, err := tls.Dial(network, addr, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				return nil, err
			}
			state := con.ConnectionState()
			for _, cert := range state.PeerCertificates {
				der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				if err != nil {
					return nil, err
				}
				if bytes.Equal(pinDer, der) {
					return con, nil
				}
				fmt.Printf("der = %+v\n", der)
			}
			return nil, fmt.Errorf("expected cert not present")
		},
	}}

	res, err = client.Get("https://127.0.0.1:60601/ping")
	if err != nil {
		t.Errorf("%v", err)
	}
	res.Body.Close()
}

func errStr(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func logErr(err error, t *testing.T) {
	if err != nil {
		t.Fatalf("unexpected error, %v", err)
	}
}
