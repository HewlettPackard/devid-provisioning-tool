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
	"context"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/HewlettPackard/devid-provisioning-tool/pkg/agent/keygen"
	"github.com/HewlettPackard/devid-provisioning-tool/pkg/common/logger"
	"github.com/HewlettPackard/devid-provisioning-tool/pkg/devid"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const (
	defaultCredentialPerm os.FileMode = 0600
)

func credentialToPEM(key *keygen.KeyInfo, rawCert []byte) ([]byte, error) {
	var b bytes.Buffer

	err := pem.Encode(&b, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rawCert,
	})
	if err != nil {
		err = fmt.Errorf("certificate PEM encoding failed: %w", err)
		return nil, err
	}

	// It's a primary key and we only save the template
	if key.PrivateBlob == nil {
		data, err := key.Template.Encode()
		if err != nil {
			err = fmt.Errorf("TPM2 template encoding failed: %w", err)
			return nil, err
		}

		err = pem.Encode(&b, &pem.Block{
			Type:  "TPM2 TEMPLATE",
			Bytes: data,
		})
		if err != nil {
			err = fmt.Errorf("TPM2 template PEM encoding failed: %w", err)
			return nil, err
		}

		return b.Bytes(), nil
	}

	err = pem.Encode(&b, &pem.Block{
		Type:  "TPM2 PRIVATE BLOB",
		Bytes: key.PrivateBlob,
	})
	if err != nil {
		err = fmt.Errorf("TPM2 private blob PEM encoding failed: %w", err)
		return nil, err
	}

	err = pem.Encode(&b, &pem.Block{
		Type:  "TPM2 PUBLIC KEY",
		Bytes: key.PublicBlob,
	})
	if err != nil {
		err = fmt.Errorf("TPM2 public key PEM encoding failed: %w", err)
		return nil, err
	}

	return b.Bytes(), nil
}

func doEnrollSequence(
	ctx context.Context,
	conn *grpc.ClientConn,
	requestData, requestSig []byte,
	activator func(credentialBlob, secret []byte) ([]byte, error),
) (attestCert, devIDCert []byte, err error) {
	log := logger.Using(ctx)

	log.Debug("Starting enroll stream")
	stream, err := startEnrollStream(ctx, conn)
	if err != nil {
		err = fmt.Errorf("starting enroll stream failed: %w", err)
		return
	}

	log.Debug("Sending signing request")
	err = stream.sendSigningRequest(requestData, requestSig)
	if err != nil {
		err = fmt.Errorf("sending signing request failed: %w", err)
		return
	}

	log.Debug("Receiving challenge")
	credentialBlob, secret, err := stream.recvChallenge()
	if err != nil {
		err = fmt.Errorf("receiving challenge failed: %w", err)
		return
	}

	log.Debug("Activating credential (a.k.a. solving challenge)")
	challengeResponse, err := activator(credentialBlob, secret)
	if err != nil {
		err = fmt.Errorf("challenge activation failed: %w", err)
		return
	}

	log.Debug("Sending challenge response")
	err = stream.sendChallengeResponse(challengeResponse)
	if err != nil {
		err = fmt.Errorf("sending challenge response failed: %w", err)
		return
	}

	log.Debug("Receiving signed certificates")
	attestCert, devIDCert, err = stream.recvSignedCertificates()
	if err != nil {
		err = fmt.Errorf("receiving signed certificates failed: %w", err)
		return
	}

	return attestCert, devIDCert, nil
}

func getKeygen() *keygen.Keygen {
	srkTemplateHighRSA := tpm2tools.SRKTemplateRSA()
	srkTemplateHighRSA.RSAParameters.ModulusRaw = []byte{}

	return keygen.New(keygen.UseSRKTemplate(srkTemplateHighRSA))
}

func createRawRequest(ctx context.Context, rw io.ReadWriter, pi pkix.Name) (data, signature []byte, resources *devid.RequestResources, err error) {
	log := logger.Using(ctx)

	log.Debug("Creating CSR")
	csr, resources, err := devid.CreateSigningRequest(ctx, getKeygen(), rw)
	if err != nil {
		err = fmt.Errorf("CSR creation failed: %w", err)
		return
	}

	defer func() {
		// Flush contexts on error
		if err != nil {
			resources.Flush()
			resources = nil
		}
	}()

	csr.PlatformIdentity = pi.ToRDNSequence()

	log.Debug("Marshaling CSR")
	requestData, err := csr.MarshalBinary()
	if err != nil {
		err = fmt.Errorf("CSR marshal failed: %w", err)
		return
	}

	log.Debug("Signing CSR")
	requestSig, err := devid.HashAndSign(rw, tpm2.HandleOwner, resources.DevID.Handle, requestData)
	if err != nil {
		err = fmt.Errorf("CSR signing failed: %w", err)
		return
	}

	data = requestData
	signature = requestSig
	return
}

func writeCredentials(cfg *LoadedConfig, resources *devid.RequestResources, attestCert, devIDCert []byte) error {
	// Write DevID certificate
	var devIDCertPem bytes.Buffer
	err := pem.Encode(&devIDCertPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: devIDCert,
	})
	if err != nil {
		return fmt.Errorf("certificate PEM encoding failed: %w", err)
	}
	err = ioutil.WriteFile(cfg.DevIDCertPath, devIDCertPem.Bytes(), defaultCredentialPerm)
	if err != nil {
		return fmt.Errorf("writing DevID certificate at %q failed: %w", cfg.DevIDCertPath, err)
	}

	// Write DevID private blob
	err = ioutil.WriteFile(cfg.DevIDPrivPath, resources.DevID.PrivateBlob, defaultCredentialPerm)
	if err != nil {
		return fmt.Errorf("writing DevID private key at %q failed: %w", cfg.DevIDPrivPath, err)
	}

	// Write DevID public blob
	err = ioutil.WriteFile(cfg.DevIDPubPath, resources.DevID.PublicBlob, defaultCredentialPerm)
	if err != nil {
		return fmt.Errorf("writing DevID public key at %q failed: %w", cfg.DevIDPubPath, err)
	}

	return nil
}

func run(ctx context.Context, cfg *LoadedConfig) error {
	log := logger.Using(ctx)

	log.Infof("Opening TPM device %q", cfg.TPMPath)
	rwc, err := tpm2.OpenTPM(cfg.TPMPath)
	if err != nil {
		return fmt.Errorf("opening TPM device at %q failed: %w", cfg.TPMPath, err)
	}

	defer rwc.Close()

	// Fail-fast dialing before creating TPM keys
	log.Infof("Connecting to provisioning server %q", cfg.ServerAddress)
	conn, err := grpc.Dial(cfg.ServerAddress, cfg.DialOptions...)
	if err != nil {
		return err
	}

	log.Info("Preparing signing request")
	requestData, requestSig, resources, err := createRawRequest(ctx, rwc, cfg.PlatformIdentity)
	if err != nil {
		return err
	}

	defer func() {
		log.Debug("Flushing TPM resources")
		resources.Flush()
	}()

	attestCert, devIDCert, err := doEnrollSequence(ctx, conn, requestData, requestSig, resources.Activate)
	if err != nil {
		err = fmt.Errorf("enrollment process failed: %w", err)
		return err
	}

	log.Info("Writing credentials to disk")
	err = writeCredentials(cfg, resources, attestCert, devIDCert)
	if err != nil {
		err = fmt.Errorf("writing credentials failed: %w", err)
		return err
	}

	return nil
}

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	log := logger.StandardLogger()
	ctx := logger.ContextWithLogger(context.Background(), log)

	cfg, err := parseConfig()
	if err != nil {
		log.Fatalf("Parsing configuration failed: %v", err)
	}

	lcfg, err := loadConfig(cfg)
	if err != nil {
		log.Fatalf("Load resources failed: %v", err)
	}

	err = run(ctx, lcfg)
	if err != nil {
		log.Fatalf("Provisioning failed: %v", err)
	}
}
