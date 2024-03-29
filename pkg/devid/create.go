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
package devid

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/HewlettPackard/devid-provisioning-tool/pkg/agent/keygen"
	"github.com/HewlettPackard/devid-provisioning-tool/pkg/common/logger"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const EKRSACertificateHandle = tpmutil.Handle(0x01c00002)

func parseCertificateWithTrailingData(asn1Data []byte) (*x509.Certificate, error) {
	var value asn1.RawValue
	_, err := asn1.Unmarshal(asn1Data, &value)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(value.FullBytes)
}

func CreateSigningRequest(ctx context.Context, kgen *keygen.Keygen, rw io.ReadWriter) (request *SigningRequest, resources *RequestResources, err error) {
	log := logger.Using(ctx)

	resources = &RequestResources{rw: rw}
	defer func() {
		// Flush contexts on error
		if err != nil {
			resources.Flush()
			resources = nil
		}
	}()

	log.Infof("Reading EK certificate from NV index %08x", EKRSACertificateHandle)
	ekCertData, err := tpm2.NVRead(rw, EKRSACertificateHandle)
	if err != nil {
		err = fmt.Errorf("reading NV index %08x failed: %w", EKRSACertificateHandle, err)
		return
	}

	log.Debug("Parsing EK certificate")
	ekCert, err := parseCertificateWithTrailingData(ekCertData)
	if err != nil {
		err = fmt.Errorf("parsing EK certificate failed: %w", err)
		return
	}

	// Extra: load and include full EK public into the CSR in order to
	// support EKs created using a custom template.
	log.Info("Get Endorsement Key (RSA)")
	ek, err := kgen.CreateEndorsementKey(rw)
	if err != nil {
		return
	}

	// Don't defer handler flushing
	resources.Endorsement = ek

	log.Info("Get Attestation Key (RSA)")
	ak, err := kgen.CreateAttestationKey(rw)
	if err != nil {
		return
	}

	// Don't defer handler flushing
	resources.Attestation = ak

	log.Info("Get DevID (RSA)")
	devID, err := kgen.CreateDevIDKey(rw)
	if err != nil {
		return
	}

	// Don't defer handler flushing
	resources.DevID = devID

	log.Info("Certifying TPM-residency of keys")
	certifyBytes, certifySig, err := certify(rw, devID.Handle, ak.Handle)
	if err != nil {
		err = fmt.Errorf("tpm2.Certify failed: %w", err)
		return
	}

	log.Info("CSR creation complete! [3]")
	request = &SigningRequest{
		EndorsementCertificate: ekCert,
		EndorsementKey:         &ek.Public,

		AttestationKey: &ak.Public,
		DevIDKey:       &devID.Public,

		CertifyData:      certifyBytes,
		CertifySignature: certifySig,
	}

	return
}

func certify(rw io.ReadWriter, object, signer tpmutil.Handle) ([]byte, []byte, error) {
	maxAttempts := 5
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		certifyBytes, certifySig, err := tpm2.Certify(rw, "", "", object, signer, nil)
		switch {
		case err == nil:
			return certifyBytes, certifySig, nil
		case isRetry(err):
			time.Sleep(time.Millisecond * 500)
		default:
			return nil, nil, err
		}
	}

	return nil, nil, fmt.Errorf("max attempts reached while trying to certify key")
}

// isRetry returns true if the given error is a tpm2.Warning that requests retry.
func isRetry(err error) bool {
	target := &tpm2.Warning{Code: tpm2.RCRetry}
	if errors.As(err, target) && target.Code == tpm2.RCRetry {
		return true
	}
	return false
}
