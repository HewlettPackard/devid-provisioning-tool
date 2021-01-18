package common

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func ReadCertificatesFromPEMFiles(certPool *x509.CertPool, filenames ...string) error {
	for _, filename := range filenames {
		pemCerts, err := ioutil.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("could not read file %q: %w", filename, err)
		}

		err = LoadCertificatesFromPEM(certPool, pemCerts)
		if err != nil {
			return fmt.Errorf("could not load certificates from %q: %w", filename, err)
		}
	}

	return nil
}

func LoadCertificatesFromPEM(certPool *x509.CertPool, pemCerts []byte) error {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing certificate failed: %w", err)
		}

		certPool.AddCert(cert)
	}

	return nil
}
