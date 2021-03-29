// (C) Copyright 2021 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
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
