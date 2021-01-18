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
