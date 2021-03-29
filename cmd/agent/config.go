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
	defaultTPMPath              = "/dev/tpmrm0"
	defaultCredentialDir        = "."
	defaultOutDevIDCertFilename = "devid-certificate.der"
	defaultOutDevIDPrivFilename = "devid-private-key.blob"
	defaultOutDevIDPubFilename  = "devid-public-key.blob"
	defaultOutAKCertFilename    = "ak-certificate.der"
	defaultOutAKPrivFilename    = "ak-private-key.blob"
	defaultOutAKPubFilename     = "ak-public-key.blob"
	defaultOutDevIDCredFilename = ""
	defaultOutAKCredFilename    = ""
	defaultServerPort           = 8443
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
	CAPath             *string `hcl:"server_bundle_path"`

	OutCredentialsDir string `hcl:"out_dir,optional"`

	OutDevIDCertFilename string `hcl:"out_devid_cert,optional"`
	OutDevIDPrivFilename string `hcl:"out_devid_priv,optional"`
	OutDevIDPubFilename  string `hcl:"out_devid_pub,optional"`
	OutDevIDCredFilename string `hcl:"out_devid_credential,optional"`

	OutAKCertFilename string `hcl:"out_ak_cert,optional"`
	OutAKPrivFilename string `hcl:"out_ak_priv,optional"`
	OutAKPubFilename  string `hcl:"out_ak_pub,optional"`
	OutAKCredFilename string `hcl:"out_ak_credential,optional"`

	SerialNumber  string                    `hcl:"serial_number,optional"`
	CommonName    string                    `hcl:"common_name,optional"`
	SubjectExtras *common.DistinguishedName `hcl:"subject_extras,block"`
}

func parseConfig() (*AgentConfig, error) {
	flag.Parse()
	givenFlags = getGivenFlags()

	parser := hclparse.NewParser()
	f, err := parser.ParseHCLFile(*flagConfigPath)
	if err != nil {
		return nil, err
	}

	var ac AgentConfig
	err = gohcl.DecodeBody(f.Body, nil, &ac)
	if err != nil {
		return nil, err
	}

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

	return &ac, nil
}

type LoadedConfig struct {
	TPMPath string

	ServerAddress string
	DialOptions   []grpc.DialOption

	DevIDCertPath string
	DevIDPrivPath string
	DevIDPubPath  string
	DevIDCredPath string

	AKCertPath string
	AKPrivPath string
	AKPubPath  string
	AKCredPath string

	PlatformIdentity pkix.Name
}

func loadConfig(ac *AgentConfig) (*LoadedConfig, error) {
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
	dialOpts := []grpc.DialOption{}
	if ac.InsecureConnection {
		dialOpts = append(dialOpts, grpc.WithInsecure())
	} else {
		creds := credentials.NewClientTLSFromCert(rootCAs, "")
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	}

	// Credential directory
	if ac.OutCredentialsDir == "" {
		ac.OutCredentialsDir = defaultCredentialDir
	}

	// DevID
	if ac.OutDevIDCertFilename == "" {
		ac.OutDevIDCertFilename = defaultOutDevIDCertFilename
	}
	if ac.OutDevIDPrivFilename == "" {
		ac.OutDevIDPrivFilename = defaultOutDevIDPrivFilename
	}
	if ac.OutDevIDPubFilename == "" {
		ac.OutDevIDPubFilename = defaultOutDevIDPubFilename
	}

	outDevIDCredPath := ""
	if ac.OutDevIDCredFilename != "" {
		outDevIDCredPath = filepath.Join(ac.OutCredentialsDir, ac.OutDevIDCredFilename)
	}

	// AK
	if ac.OutAKCertFilename == "" {
		ac.OutAKCertFilename = defaultOutAKCertFilename
	}
	if ac.OutAKPrivFilename == "" {
		ac.OutAKPrivFilename = defaultOutAKPrivFilename
	}
	if ac.OutAKPubFilename == "" {
		ac.OutAKPubFilename = defaultOutAKPubFilename
	}

	outAKCredPath := ""
	if ac.OutAKCredFilename != "" {
		outDevIDCredPath = filepath.Join(ac.OutCredentialsDir, ac.OutAKCredFilename)
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

		DevIDCertPath: filepath.Join(ac.OutCredentialsDir, ac.OutDevIDCertFilename),
		DevIDPrivPath: filepath.Join(ac.OutCredentialsDir, ac.OutDevIDPrivFilename),
		DevIDPubPath:  filepath.Join(ac.OutCredentialsDir, ac.OutDevIDPubFilename),
		DevIDCredPath: outDevIDCredPath,

		AKCertPath: filepath.Join(ac.OutCredentialsDir, ac.OutAKCertFilename),
		AKPrivPath: filepath.Join(ac.OutCredentialsDir, ac.OutAKPrivFilename),
		AKPubPath:  filepath.Join(ac.OutCredentialsDir, ac.OutAKPubFilename),
		AKCredPath: outAKCredPath,

		PlatformIdentity: platformIdentity,
	}, nil
}
