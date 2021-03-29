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
package x509tcg

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

type generalName struct {
	OtherName otherName `asn1:"tag:0"`
}

type otherName struct {
	TypeID asn1.ObjectIdentifier
	Value  interface{} `asn1:"tag:0"`
}

type hardwareModuleName struct {
	Type         asn1.ObjectIdentifier
	SerialNumber []byte
}

type permanentIdentifier struct {
	IdentifierValue string                `asn1:"optional,utf8"`
	Assigner        asn1.ObjectIdentifier `asn1:"optional"`
}

func buildSAN(subjectIsEmpty bool, serialNumber []byte, value string) (pkix.Extension, error) {
	names := []generalName{
		{
			OtherName: otherName{
				TypeID: oidOnHardwareModuleName,
				Value: hardwareModuleName{
					Type:         oidTCGHardwareTypeTPM2,
					SerialNumber: serialNumber,
				},
			},
		},
		{
			OtherName: otherName{
				TypeID: oidOnPermanentIdentifier,
				Value: permanentIdentifier{
					IdentifierValue: value,
					Assigner:        oidTCGOnEKPermIDSha256,
				},
			},
		},
	}

	data, err := asn1.Marshal(names)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       oidSubjectAltName,
		Critical: subjectIsEmpty,
		Value:    data,
	}, nil
}

func findSAN(cert *x509.Certificate) []byte {
	for _, ext := range cert.Extensions {
		if oidSubjectAltName.Equal(ext.Id) {
			return ext.Value
		}
	}

	return nil
}
