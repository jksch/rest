package rest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/mail"
	"os"
	"time"
)

const (
	defaultValidFor = 24 * 365 * time.Hour
	defaultRASBits  = 4096
)

var (
	defaultKeyOut = func() (io.WriteCloser, error) {
		return os.OpenFile("key.pem", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	}
	defaultCertOut = func() (io.WriteCloser, error) {
		return os.OpenFile("cert.pem", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	}
)

type (
	serialRes struct {
		serialNumber *big.Int
		err          error
	}
	certRes struct {
		cert []byte
		err  error
	}
)

// CertConf holds the TLS certificate configuration.
type CertConf struct {
	ValidFor  time.Duration
	RASBits   int
	Subject   pkix.Name
	CertOut   func() (io.WriteCloser, error) // Will write to the writer and then close.
	KeyOut    func() (io.WriteCloser, error) // Will write to the writer and then close.
	Random    io.Reader
	HostAddrs []string
}

// NewCertConf returns a default certificate configuration for the given subject and hostAddrs.
// Default valid for is 365 days.
// Default cert RSA bits 4096.
// Default cert out ./cert.pem
// Default key out ./key.pem
func NewCertConf(subject pkix.Name, hostAddrs []string) CertConf {
	return CertConf{
		ValidFor:  defaultValidFor,
		RASBits:   defaultRASBits,
		Subject:   subject,
		KeyOut:    defaultKeyOut,
		CertOut:   defaultCertOut,
		Random:    rand.Reader,
		HostAddrs: hostAddrs,
	}
}

// GenerateTLSCertificate generates a TLS cert specified by the given configuration asynchronously.
//
// Caution: Before using this consider using a secure certificate from https://letsencrypt.org/.
// Since a self signed certificate is less secure than a proper one.
// Mainly because the identity of the server using this self signed certificate cannot be confirmed.
// Which makes it especially vulnerable for man in the middle attacks.
// Do not use this with public servers!
//
// For more information see:
// https://en.wikipedia.org/wiki/Self-signed_certificate#Security_issues.
// https://en.wikipedia.org/wiki/Man-in-the-middle_attack
//
// For https://letsencrypt.org/ in go. You can use:
// https://github.com/ericchiang/letsencrypt to get the cert.
func GenerateTLSCertificate(conf CertConf) error {

	serial := generateSerilaNumber(conf)
	key, err := rsa.GenerateKey(conf.Random, conf.RASBits)
	if err != nil {
		return fmt.Errorf("could not generate RSA key, %v", err)
	}

	cert := generateCert(conf, key, serial)
	writeKey := writeKeyPem(conf, key)
	writeCert := writeCertPem(conf, cert)

	errKey := <-writeKey
	errCert := <-writeCert
	if errKey != nil {
		return errKey
	}
	if errCert != nil {
		return errCert
	}

	return nil
}

func generateSerilaNumber(conf CertConf) <-chan serialRes {
	back := make(chan serialRes)
	res := serialRes{}
	go func() {

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		res.serialNumber, res.err = rand.Int(conf.Random, serialNumberLimit)
		back <- res

	}()
	return back
}

func generateCert(conf CertConf, key *rsa.PrivateKey, serial <-chan serialRes) <-chan certRes {
	call := make(chan certRes, 1)
	res := certRes{}

	serialRes := <-serial
	if serialRes.err != nil {
		res.err = serialRes.err
		call <- res
		return call
	}

	go func() {
		notBefore := time.Now()
		notAfter := notBefore.Add(conf.ValidFor)

		template := x509.Certificate{
			SerialNumber: serialRes.serialNumber,
			Subject:      conf.Subject,
			Issuer:       conf.Subject,
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
			BasicConstraintsValid: true,
		}

		for _, addr := range conf.HostAddrs {
			if ip := net.ParseIP(addr); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else if _, err := mail.ParseAddress(addr); err == nil {
				template.EmailAddresses = append(template.EmailAddresses, addr)
			} else {
				template.DNSNames = append(template.DNSNames, addr)
			}
		}

		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign

		res.cert, res.err = x509.CreateCertificate(
			conf.Random,
			&template,
			&template,
			&key.PublicKey,
			key,
		)
		call <- res
	}()

	return call
}

func writeCertPem(conf CertConf, cert <-chan certRes) <-chan error {
	call := make(chan error, 1)
	certRes := <-cert
	if certRes.err != nil {
		call <- certRes.err
		return call
	}

	go func() {
		certOut, err := conf.CertOut()
		if err != nil {
			call <- fmt.Errorf("could not open cert out, %v", err)
			return
		}
		defer certOut.Close()

		if err := pem.Encode(certOut, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certRes.cert,
		}); err != nil {
			call <- err
			return
		}
		call <- nil
	}()

	return call
}

func writeKeyPem(conf CertConf, key *rsa.PrivateKey) <-chan error {
	call := make(chan error)

	go func() {
		keyOut, err := conf.KeyOut()
		if err != nil {
			call <- fmt.Errorf("could not open key out, %v", err)
			return
		}
		defer keyOut.Close()

		if err := pem.Encode(keyOut, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}); err != nil {
			call <- fmt.Errorf("could not write key, %v", err)
			return
		}
		call <- nil
	}()

	return call
}
