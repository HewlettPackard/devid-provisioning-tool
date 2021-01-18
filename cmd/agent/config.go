package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"path/filepath"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.hpe.com/langbeck/tpm2-keys/pkg/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultTPMPath       = "/dev/tpmrm0"
	defaultFilenameDevID = "devid.pem"
	defaultFilenameAK    = "ak.pem"
	defaultServerPort    = 8443
)

const (
	fnameTPMPath       = "tpmPath"
	fnameServerAddress = "serverAddress"
	fnameServerPort    = "serverPort"
	fnameInsecure      = "insecure"
	fnameSerialNumber  = "serialNumber"
	fnameCommonName    = "commonName"
)

var (
	flagConfigPath    = flag.String("config", "agent.conf", "Agent configuration file")
	flagTPMPath       = flag.String(fnameTPMPath, defaultTPMPath, "Location of the TPM device")
	flagServerAddress = flag.String(fnameServerAddress, "", "IP address or DNS name of the provisioning server")
	flagServerPort    = flag.Int(fnameServerPort, defaultServerPort, "Port number of the provisioning server")
	flagInsecure      = flag.Bool(fnameInsecure, false, "Don't verify the server's identity")
	flagSerialNumber  = flag.String(fnameSerialNumber, "", "Platform Serial Number")
	flagCommonName    = flag.String(fnameCommonName, "", "Platform Common Name")
)

var givenFlags map[string]bool

func getGivenFlags() map[string]bool {
	givenFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		givenFlags[f.Name] = true
	})

	return givenFlags
}

type AgentConfig struct {
	TPMPath *string `hcl:"tpm_path"`

	ServerAddress      string  `hcl:"server_address"`
	ServerPort         *int    `hcl:"server_port"`
	InsecureConnection bool    `hcl:"insecure_connection,optional"`
	CAPath             *string `hcl:"ca_path"`

	OutputCredentialsDir *string `hcl:"output_credentials_dir"`
	OutputDevIDPath      *string `hcl:"output_devid_path"`
	OutputAKPath         *string `hcl:"output_ak_path"`

	SerialNumber  string                    `hcl:"serial_number,optional"`
	CommonName    string                    `hcl:"common_name,optional"`
	SubjectExtras *common.DistinguishedName `hcl:"subject_extras,block"`
}

type ConfigBase struct {
	AgentConfig AgentConfig `hcl:"agent,block"`
}

func parseConfig() (*ConfigBase, error) {
	flag.Parse()
	givenFlags = getGivenFlags()

	parser := hclparse.NewParser()
	f, err := parser.ParseHCLFile(*flagConfigPath)
	if err != nil {
		return nil, err
	}

	var cfg ConfigBase
	err = gohcl.DecodeBody(f.Body, nil, &cfg)
	if err != nil {
		return nil, err
	}

	ac := &cfg.AgentConfig

	// TPMPath
	if givenFlags[fnameTPMPath] || ac.TPMPath == nil {
		ac.TPMPath = flagTPMPath
	}

	// ServerAddress
	if givenFlags[fnameServerAddress] {
		ac.ServerAddress = *flagServerAddress
	}

	// ServerPort
	if givenFlags[fnameServerPort] || ac.ServerPort == nil {
		ac.ServerPort = flagServerPort
	}

	serverPort := *ac.ServerPort
	if serverPort < 0 || serverPort > 0xFFFF {
		return nil, fmt.Errorf("server port out of range: %d", serverPort)
	}

	// InsecureConnection
	if givenFlags[fnameInsecure] {
		ac.InsecureConnection = *flagInsecure
	}

	// CommonName
	if givenFlags[fnameCommonName] {
		ac.CommonName = *flagCommonName
	}

	// SerialNumber
	if givenFlags[fnameSerialNumber] {
		ac.SerialNumber = *flagSerialNumber
	}

	return &cfg, nil
}

type LoadedConfig struct {
	TPMPath string

	ServerAddress string
	DialOptions   []grpc.DialOption

	DevIDPath string
	AKPath    string

	PlatformIdentity pkix.Name
}

func loadConfig(cfg *ConfigBase) (*LoadedConfig, error) {
	ac := cfg.AgentConfig

	var rootCAs *x509.CertPool
	if ac.CAPath != nil {
		rootCAs = x509.NewCertPool()
		err := common.ReadCertificatesFromPEMFiles(rootCAs, *ac.CAPath)
		if err != nil {
			return nil, err
		}

	} else {
		// Fallback to use system certificates
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system certificates: %w", err)
		}

		rootCAs = certPool
	}

	// TPMPath
	tpmPath := filepath.Clean(*ac.TPMPath)

	// DialOptions
	dialOpts := []grpc.DialOption{grpc.WithBlock()}
	if ac.InsecureConnection {
		dialOpts = append(dialOpts, grpc.WithInsecure())
	} else {
		creds := credentials.NewClientTLSFromCert(rootCAs, "")
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	}

	credentialDir := "."
	if ac.OutputCredentialsDir != nil {
		credentialDir = filepath.Clean(*ac.OutputCredentialsDir)
	}

	// DevIDPath
	var devidPath string
	if ac.OutputDevIDPath != nil {
		devidPath = filepath.Clean(*ac.OutputDevIDPath)
	} else {
		devidPath = filepath.Join(credentialDir, defaultFilenameDevID)
	}

	// AKPath
	var akPath string
	if ac.OutputAKPath != nil {
		akPath = filepath.Clean(*ac.OutputAKPath)
	} else {
		akPath = filepath.Join(credentialDir, defaultFilenameAK)
	}

	// PlatformIdentity
	var platformIdentity pkix.Name
	ac.SubjectExtras.AppendInto(&platformIdentity)
	platformIdentity.SerialNumber = ac.SerialNumber
	platformIdentity.CommonName = ac.CommonName

	return &LoadedConfig{
		TPMPath: tpmPath,

		ServerAddress: fmt.Sprintf("%s:%d", ac.ServerAddress, *ac.ServerPort),
		DialOptions:   dialOpts,

		DevIDPath: devidPath,
		AKPath:    akPath,

		PlatformIdentity: platformIdentity,
	}, nil
}
