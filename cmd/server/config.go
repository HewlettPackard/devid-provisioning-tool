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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.hpe.com/langbeck/tpm2-keys/pkg/common"
	"github.hpe.com/langbeck/tpm2-keys/pkg/x509ca"
)

const (
	defaultBindAddress = "0.0.0.0"
	defaultBindPort    = 8443
)

const (
	fnameBindAddress = "bindAddress"
	fnameBindPort    = "bindPort"
)

var (
	flagConfigPath  = flag.String("config", "server.conf", "Server configuration file")
	flagBindAddress = flag.String(fnameBindAddress, defaultBindAddress, "IP address or DNS name of the provisioning server")
	flagBindPort    = flag.Int(fnameBindPort, defaultBindPort, "Port number of the provisioning server")
)

var givenFlags map[string]bool

func getGivenFlags() map[string]bool {
	givenFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		givenFlags[f.Name] = true
	})

	return givenFlags
}

type CAInfo struct {
	CertificatePath string  `hcl:"certificate_path"`
	PrivateKeyPath  *string `hcl:"private_key_path"`

	SubjectExtras *common.DistinguishedName `hcl:"subject_extras,block"`
}

type ServerConfig struct {
	BindAddress           *string  `hcl:"bind_address"`
	BindPort              *int     `hcl:"bind_port"`
	CertificatePath       string   `hcl:"certificate_path,optional"`
	PrivateKeyPath        string   `hcl:"private_key_path,optional"`
	EndorsementBundlePath []string `hcl:"endorsement_bundle_paths"`
	CAInfo                CAInfo   `hcl:"ca,block"`
}

func parseConfig() (*ServerConfig, error) {
	flag.Parse()

	parser := hclparse.NewParser()
	f, err := parser.ParseHCLFile(*flagConfigPath)
	if err != nil {
		return nil, err
	}

	var sc ServerConfig
	err = gohcl.DecodeBody(f.Body, nil, &sc)
	if err != nil {
		return nil, err
	}

	// BindAddress
	if givenFlags[fnameBindAddress] || sc.BindAddress == nil {
		sc.BindAddress = flagBindAddress
	}

	// BindPort
	if givenFlags[fnameBindPort] || sc.BindPort == nil {
		sc.BindPort = flagBindPort
	}

	bindPort := *sc.BindPort
	if bindPort < 0 || bindPort > 0xFFFF {
		return nil, fmt.Errorf("bind port out of range: %d", bindPort)
	}

	return &sc, nil
}

type LoadedConfig struct {
	BindAddress          string
	CertificateAuthority x509ca.CertificateAuthority
	EndorsementRoots     *x509.CertPool
	TLSCertificate       *tls.Certificate

	SubjectExtras *common.DistinguishedName
}

func loadConfig(sc *ServerConfig) (*LoadedConfig, error) {
	caInfo := sc.CAInfo

	var certPEMBlock, keyPEMBlock []byte
	var err error

	certPEMBlock, err = ioutil.ReadFile(caInfo.CertificatePath)
	if err != nil {
		err = fmt.Errorf("could not read CA certificate PEM file %q: %w", caInfo.CertificatePath, err)
		return nil, err
	}

	if caInfo.PrivateKeyPath != nil {
		keyPEMBlock, err = ioutil.ReadFile(*caInfo.PrivateKeyPath)
		if err != nil {
			err = fmt.Errorf("could not read CA private key PEM file %q: %w", *caInfo.PrivateKeyPath, err)
			return nil, err
		}
	}

	ca, err := x509ca.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		err = fmt.Errorf("could not create CA: %w", err)
		return nil, err
	}

	var tlsCertificate tls.Certificate
	switch {
	case sc.CertificatePath == "" && sc.PrivateKeyPath == "":
		log.Println("No TLS credentials provided, serving insecure connection")

	case sc.CertificatePath == "":
		return nil, fmt.Errorf("empty certificate_path")

	case sc.PrivateKeyPath == "":
		return nil, fmt.Errorf("empty private_key_path")

	default:
		tlsCertificate, err = tls.LoadX509KeyPair(caInfo.CertificatePath, *caInfo.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("cannot load key pair: %v", err)
		}
	}

	endorsementRoots := x509.NewCertPool()
	err = common.ReadCertificatesFromPEMFiles(endorsementRoots, sc.EndorsementBundlePath...)
	if err != nil {
		err = fmt.Errorf("could not load EK root CAs: %w", err)
		return nil, err
	}

	if len(endorsementRoots.Subjects()) == 0 {
		err = errors.New("no endorsement CA certificates loaded")
		return nil, err
	}

	return &LoadedConfig{
		BindAddress:          fmt.Sprintf("%s:%d", *sc.BindAddress, *sc.BindPort),
		EndorsementRoots:     endorsementRoots,
		CertificateAuthority: ca,
		SubjectExtras:        sc.CAInfo.SubjectExtras,
		TLSCertificate:       &tlsCertificate,
	}, nil
}
