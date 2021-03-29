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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	enrollapi "github.com/HewlettPackard/devid-provisioning-tool/proto/enrollapi"
	"github.com/google/go-tpm/tpm2"
	"google.golang.org/protobuf/proto"
)

var (
	ErrTrailingData = errors.New("ASN.1 trailing data")
)

type SigningRequest struct {
	PlatformIdentity pkix.RDNSequence

	EndorsementCertificate *x509.Certificate
	EndorsementKey         *tpm2.Public

	AttestationKey *tpm2.Public
	DevIDKey       *tpm2.Public

	CertifyData      []byte
	CertifySignature []byte
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (sr *SigningRequest) UnmarshalBinary(data []byte) error {
	var pbReq enrollapi.SigningRequest

	err := proto.Unmarshal(data, &pbReq)
	if err != nil {
		return err
	}

	if pbReq.PlatformIdentity != nil {
		rest, err := asn1.Unmarshal(pbReq.PlatformIdentity, &sr.PlatformIdentity)
		if err != nil {
			return fmt.Errorf("could not unmarshal %T: %w", sr.PlatformIdentity, err)
		}

		if len(rest) > 0 {
			return ErrTrailingData
		}
	}

	if pbReq.EndorsementCertificate != nil {
		cert, err := x509.ParseCertificate(pbReq.EndorsementCertificate)
		if err != nil {
			return fmt.Errorf("could not parse endorsement certificate: %w", err)
		}

		sr.EndorsementCertificate = cert
	}

	if pbReq.EndorsementKey != nil {
		pub, err := tpm2.DecodePublic(pbReq.EndorsementKey)
		if err != nil {
			return fmt.Errorf("could not decode EK: %w", err)
		}

		sr.EndorsementKey = &pub
	}

	if pbReq.AttestationKey != nil {
		pub, err := tpm2.DecodePublic(pbReq.AttestationKey)
		if err != nil {
			return fmt.Errorf("could not decode AK: %w", err)
		}

		sr.AttestationKey = &pub
	}

	if pbReq.DevIDKey != nil {
		pub, err := tpm2.DecodePublic(pbReq.DevIDKey)
		if err != nil {
			return fmt.Errorf("could not decode DevID: %w", err)
		}

		sr.DevIDKey = &pub
	}

	if pbReq.CertifyData != nil {
		sr.CertifyData = append([]byte{}, pbReq.CertifyData...)
	}

	if pbReq.CertifySignature != nil {
		sr.CertifySignature = pbReq.CertifySignature
	}

	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler
func (sr *SigningRequest) MarshalBinary() (data []byte, err error) {
	var pbReq enrollapi.SigningRequest

	pbReq.PlatformIdentity, err = asn1.Marshal(sr.PlatformIdentity)
	if err != nil {
		return nil, fmt.Errorf("could not marshal %T: %w", sr.PlatformIdentity, err)
	}

	if sr.EndorsementCertificate != nil {
		pbReq.EndorsementCertificate = append([]byte{}, sr.EndorsementCertificate.Raw...)
	}

	if sr.EndorsementKey != nil {
		data, err := sr.EndorsementKey.Encode()
		if err != nil {
			return nil, fmt.Errorf("could not encode EK: %w", err)
		}

		pbReq.EndorsementKey = data
	}

	if sr.AttestationKey != nil {
		data, err := sr.AttestationKey.Encode()
		if err != nil {
			return nil, fmt.Errorf("could not encode AK: %w", err)
		}

		pbReq.AttestationKey = data
	}

	if sr.DevIDKey != nil {
		data, err := sr.DevIDKey.Encode()
		if err != nil {
			return nil, fmt.Errorf("could not encode DevID: %w", err)
		}

		pbReq.DevIDKey = data
	}

	if sr.CertifyData != nil {
		pbReq.CertifyData = append([]byte{}, sr.CertifyData...)
	}

	if sr.CertifySignature != nil {
		pbReq.CertifySignature = append([]byte{}, sr.CertifySignature...)
	}

	return proto.Marshal(&pbReq)
}

type SigningResponse struct {
	AttestationCertificate *x509.Certificate
	DevIDCertificate       *x509.Certificate
}

// MarshalBinary implements encoding.BinaryMarshaler
func (sr *SigningResponse) MarshalBinary() (data []byte, err error) {
	var pbResp enrollapi.SigningResponse
	if sr.AttestationCertificate != nil {
		pbResp.AttestationCertificate = append([]byte{}, sr.AttestationCertificate.Raw...)
	}

	if sr.DevIDCertificate != nil {
		pbResp.DevIDCertificate = append([]byte{}, sr.DevIDCertificate.Raw...)
	}

	return proto.Marshal(&pbResp)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (sr *SigningResponse) UnmarshalBinary(data []byte) error {
	var pbResp enrollapi.SigningResponse

	err := proto.Unmarshal(data, &pbResp)
	if err != nil {
		return err
	}

	if pbResp.AttestationCertificate != nil {
		cert, err := x509.ParseCertificate(pbResp.AttestationCertificate)
		if err != nil {
			return fmt.Errorf("could not parse attestation certificate: %w", err)
		}

		sr.AttestationCertificate = cert
	}

	if pbResp.DevIDCertificate != nil {
		cert, err := x509.ParseCertificate(pbResp.DevIDCertificate)
		if err != nil {
			return fmt.Errorf("could not parse DevID certificate: %w", err)
		}

		sr.DevIDCertificate = cert
	}

	return nil
}
