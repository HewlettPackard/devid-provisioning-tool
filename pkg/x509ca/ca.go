package x509ca

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

type CertificateAuthority interface {
	Sign(template *x509.Certificate) ([]byte, error)
}

func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (CertificateAuthority, error) {
	var cert *x509.Certificate
	var key crypto.PrivateKey
	var block *pem.Block
	var err error

	for {
		block, certPEMBlock = pem.Decode(certPEMBlock)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
		}

		if keyPEMBlock == nil && block.Type == "PRIVATE KEY" {
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		}
	}

	if keyPEMBlock != nil {
		for {
			block, keyPEMBlock = pem.Decode(keyPEMBlock)
			if block == nil {
				break
			}

			if block.Type == "PRIVATE KEY" {
				key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return &certificateAuthority{
		cert: cert,
		key:  key,
	}, nil
}

type certificateAuthority struct {
	cert *x509.Certificate
	key  crypto.PrivateKey
}

func (ca *certificateAuthority) uniqueSerialNumber(template *x509.Certificate) (*big.Int, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(template.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	subjData, err := asn1.Marshal(template.Subject)
	if err != nil {
		return nil, err
	}

	h := sha1.New()
	h.Write(ca.cert.Raw)
	h.Write(subjData)
	h.Write(pubBytes)

	sn := template.SerialNumber
	if sn != nil {
		h.Write(sn.Bytes())
	}

	return new(big.Int).SetBytes(h.Sum(nil)), nil
}

func (ca *certificateAuthority) Sign(template *x509.Certificate) ([]byte, error) {
	if template.PublicKey == nil {
		return nil, errors.New("missing public key")
	}

	sn, err := ca.uniqueSerialNumber(template)
	if err != nil {
		return nil, fmt.Errorf("failed to generate an unique serial number: %w", err)
	}

	template.SerialNumber = sn

	return x509.CreateCertificate(rand.Reader, template, ca.cert, template.PublicKey, ca.key)
}
