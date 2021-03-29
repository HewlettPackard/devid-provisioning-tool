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
package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/HewlettPackard/devid-provisioning-tool/pkg/common"
	"github.com/HewlettPackard/devid-provisioning-tool/pkg/devid"
	"github.com/HewlettPackard/devid-provisioning-tool/pkg/x509ca"
	"github.com/HewlettPackard/devid-provisioning-tool/pkg/x509tcg"
	"github.com/HewlettPackard/devid-provisioning-tool/proto/enrollapi"
	"github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Context interface {
	CreateChallenge() (credentialBlob, secret, nonce []byte, err error)
	IssueAttestationCertificate() ([]byte, error)
	IssueDevIDCertificate() ([]byte, error)
}

type Method interface {
	CreateContext(data, sig []byte) (Context, error)
}

type SigningRequestMethod interface {
	DecodeAndVerifyRequest(data, sig []byte) (*devid.SigningRequest, error)
	IssueCertificates(req *devid.SigningRequest) (*devid.SigningResponse, error)
}

type DevIDService struct {
	CertificateAuthority x509ca.CertificateAuthority
	EndorsementRoots     *x509.CertPool
	SubjectExtras        *common.DistinguishedName
}

var (
	subjectAlternativeNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}
)

func (svc DevIDService) verifyEndosementCredential(pub *tpm2.Public, cert *x509.Certificate) error {
	// TODO: Compare pub against cert.PublicKey

	// Check UnhandledCriticalExtensions for OIDs that we know what to do about
	// it (e.g. it's safe to ignore)
	if len(cert.UnhandledCriticalExtensions) > 0 {
		unhandledExtensions := []asn1.ObjectIdentifier{}
		for _, oid := range cert.UnhandledCriticalExtensions {
			if oid.Equal(subjectAlternativeNameOID) {
				// Subject Alternative Name is not processed at the time.
				continue
			}
		}

		cert.UnhandledCriticalExtensions = unhandledExtensions
	}

	_, err := cert.Verify(x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     svc.EndorsementRoots,
	})
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

func (svc DevIDService) verifyDevIDResidency(pubAK, pubDevID *tpm2.Public, attestData, attestSig []byte) error {
	err := checkSignature(pubAK, attestData, attestSig)
	if err != nil {
		return err
	}

	data, err := tpm2.DecodeAttestationData(attestData)
	if err != nil {
		return err
	}

	if data.AttestedCertifyInfo == nil {
		return errors.New("missing certify info")
	}

	ok, err := data.AttestedCertifyInfo.Name.MatchesPublic(*pubDevID)
	if err != nil {
		return err
	}

	if !ok {
		return errors.New("certify failed")
	}

	return nil
}

func (svc DevIDService) CreateContext(data, sig []byte) (Context, error) {
	var sr devid.SigningRequest
	err := sr.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}

	// 7. CA verifies the received data:
	// 7a. Extract IDevID public key and verify the signature on TCG-CSR-IDEVID
	err = checkSignature(sr.DevIDKey, data, sig)
	if err != nil {
		return nil, err
	}

	// 7b. Verify the EK Certificate using the indicated TPM manufacturer's
	//     public key.
	err = svc.verifyEndosementCredential(sr.EndorsementKey, sr.EndorsementCertificate)
	if err != nil {
		return nil, fmt.Errorf("invalid EK credential: %w", err)
	}

	// 7c. Verify TPM residency of IDevID key using the IAK public key to
	//     validate the signature of the TPMB_Attest structure.
	err = svc.verifyDevIDResidency(
		sr.AttestationKey,
		sr.DevIDKey,
		sr.CertifyData,
		sr.CertifySignature,
	)
	if err != nil {
		return nil, err
	}

	// 7d. Verify the attributes of the IDevID key public area.
	err = checkDevIDProp(sr.DevIDKey.Attributes)
	if err != nil {
		return nil, fmt.Errorf("DevID key invalid attributes: %w", err)
	}

	// 7e. Verify the attributes of the IAK public area.
	err = checkAKProp(sr.AttestationKey.Attributes)
	if err != nil {
		return nil, fmt.Errorf("attestation key invalid attributes: %w", err)
	}

	// 7f. Calculate the Name of the IAK.
	akName, err := sr.AttestationKey.Name()
	if err != nil {
		return nil, err
	}

	return &context{
		ca:            svc.CertificateAuthority,
		request:       sr,
		credName:      akName,
		subjectExtras: svc.SubjectExtras,

		notBefore: time.Now().UTC(),
		notAfter:  noExpirationDate,
	}, nil
}

type context struct {
	ca            x509ca.CertificateAuthority
	request       devid.SigningRequest
	credName      tpm2.Name
	subjectExtras *common.DistinguishedName

	// OEM issued IDevID certificates (both signing and attestation) SHOULD
	// have matching notBefore and notAfter dates and times.
	notBefore, notAfter time.Time
}

func (ctx *context) CreateChallenge() (credentialBlob, secret, nonce []byte, err error) {
	return createChallenge(ctx.request.EndorsementKey, ctx.credName)
}

func (ctx *context) IssueAttestationCertificate() ([]byte, error) {
	return []byte{}, nil
}

func (ctx *context) IssueDevIDCertificate() ([]byte, error) {
	req := ctx.request

	if req.DevIDKey == nil {
		return nil, errors.New("missing DevID key")
	}

	pub, err := req.DevIDKey.Key()
	if err != nil {
		return nil, err
	}

	keyData, err := req.DevIDKey.Encode()
	if err != nil {
		return nil, err
	}

	var subj pkix.Name
	subj.FillFromRDNSequence(&req.PlatformIdentity)

	// TODO: merge with fields from subject_extras
	ctx.subjectExtras.AppendInto(&subj)

	subjectIsEmpty := len(subj.ToRDNSequence()) == 0
	sanExtension, err := x509tcg.DevIDSANFromEKCertificate(
		subjectIsEmpty,
		req.EndorsementCertificate,
	)
	if err != nil {
		return nil, err
	}

	keySha1 := sha1.Sum(keyData)
	serialNumber := new(big.Int).SetBytes(keySha1[:])

	template := x509.Certificate{
		SerialNumber: serialNumber,
		PublicKey:    pub,

		Subject: subj,

		NotBefore: ctx.notBefore,
		NotAfter:  ctx.notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,

		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			oidCapVerifiedTPMFixed,
		},

		ExtraExtensions: []pkix.Extension{
			sanExtension,
		},
	}

	return ctx.ca.Sign(&template)
}

type server struct {
	method Method
}

func (s server) Enroll(stream enrollapi.Enrollment_EnrollServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}

	request := msg.GetSigningRequest()
	if request == nil || request.Data == nil || request.Signature == nil {
		return errors.New("incomplete request")
	}

	ctx, err := s.method.CreateContext(request.Data, request.Signature)
	if err != nil {
		return err
	}

	credentialBlob, secret, nonce, err := ctx.CreateChallenge()
	if err != nil {
		return err
	}

	err = stream.Send(&enrollapi.EnrollResponse{
		ChallengeOrResponse: &enrollapi.EnrollResponse_Challenge{
			Challenge: &enrollapi.Challenge{
				CredentialBlob: credentialBlob,
				Secret:         secret,
			},
		},
	})
	if err != nil {
		return err
	}

	msg, err = stream.Recv()
	if err != nil {
		return err
	}

	response := msg.GetChallengeResponse()
	if response == nil {
		return errors.New("missing challenge response")
	}

	if !bytes.Equal(response, nonce) {
		return errors.New("challange verification failed")
	}

	attestCert, err := ctx.IssueAttestationCertificate()
	if err != nil {
		return err
	}

	devIDCert, err := ctx.IssueDevIDCertificate()
	if err != nil {
		return err
	}

	err = stream.Send(&enrollapi.EnrollResponse{
		ChallengeOrResponse: &enrollapi.EnrollResponse_SigningResponse{
			SigningResponse: &enrollapi.SigningResponse{
				AttestationCertificate: attestCert,
				DevIDCertificate:       devIDCert,
			},
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func run(cfg *LoadedConfig) error {
	l, err := net.Listen("tcp", cfg.BindAddress)
	if err != nil {
		return err
	}

	defer l.Close()

	opts := []grpc.ServerOption{}
	if cfg.TLSCertificate != nil {
		creds := credentials.NewServerTLSFromCert(cfg.TLSCertificate)
		opts = append(opts, grpc.Creds(creds))
	}

	s := grpc.NewServer(opts...)

	enrollapi.RegisterEnrollmentServer(s, server{method: DevIDService{
		CertificateAuthority: cfg.CertificateAuthority,
		EndorsementRoots:     cfg.EndorsementRoots,
		SubjectExtras:        cfg.SubjectExtras,
	}})

	err = s.Serve(l)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	cfg, err := parseConfig()
	if err != nil {
		log.Fatalf("ERROR: load configuration failed: %v", err)
	}

	lcfg, err := loadConfig(cfg)
	if err != nil {
		log.Fatalf("ERROR: load configuration resources failed: %v", err)
	}

	err = run(lcfg)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}
}
