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

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/sirupsen/logrus"
	"github.hpe.com/langbeck/tpm2-keys/pkg/agent/keygen"
	"github.hpe.com/langbeck/tpm2-keys/pkg/common/logger"
	"github.hpe.com/langbeck/tpm2-keys/pkg/devid"
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
	auroraSRKTemplate := tpm2tools.SRKTemplateRSA()
	auroraSRKTemplate.RSAParameters.ModulusRaw = []byte{}

	return keygen.New(keygen.UseSRKTemplate(auroraSRKTemplate))
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
	devIDData, err := credentialToPEM(resources.DevID, devIDCert)
	if err != nil {
		err = fmt.Errorf("DevID PEM encoding failed: %w", err)
		return err
	}

	attestData, err := credentialToPEM(resources.Attestation, attestCert)
	if err != nil {
		err = fmt.Errorf("DevID PEM encoding failed: %w", err)
		return err
	}

	err = ioutil.WriteFile(cfg.DevIDPath, devIDData, defaultCredentialPerm)
	if err != nil {
		err = fmt.Errorf("writing DevID at %q failed: %w", cfg.DevIDPath, err)
		return err
	}

	err = ioutil.WriteFile(cfg.AKPath, attestData, defaultCredentialPerm)
	if err != nil {
		err = fmt.Errorf("writing AK at %q failed: %w", cfg.AKPath, err)
		return err
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
