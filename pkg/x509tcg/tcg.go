package x509tcg

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"regexp"
)

var (
	ErrTrailingData = errors.New("ASN.1 trailing data")
	ErrNoSAN        = errors.New("no Subject Alternative Name")
)

type deviceAttributes struct {
	Manufacturer string
	Version      string
	Model        string
}

func asn1UnmarshalExactly(b []byte, val interface{}) error {
	rest, err := asn1.Unmarshal(b, val)
	if err != nil {
		return err
	}

	if len(rest) > 0 {
		return ErrTrailingData
	}

	return nil
}

func deviceAttributesFromRDNSequence(seq pkix.RDNSequence) (*deviceAttributes, error) {
	var (
		manufacturer *string
		version      *string
		model        *string
	)

	for _, rdn := range seq {
		for _, attrAndVal := range rdn {
			typ := attrAndVal.Type
			switch {
			case oidTCGAttributeTPMManufacturer.Equal(typ):
				strval := attrAndVal.Value.(string)
				manufacturer = &strval

			case oidTCGAttributeTPMVersion.Equal(typ):
				strval := attrAndVal.Value.(string)
				version = &strval

			case oidTCGAttributeTPMModel.Equal(typ):
				strval := attrAndVal.Value.(string)
				model = &strval
			}
		}
	}

	if manufacturer == nil || version == nil || model == nil {
		return nil, errors.New("missing attributes")
	}

	return &deviceAttributes{
		Manufacturer: *manufacturer,
		Version:      *version,
		Model:        *model,
	}, nil
}

func deviceAttributesFromEKCertificate(cert *x509.Certificate) (*deviceAttributes, error) {
	sanBytes := findSAN(cert)
	if sanBytes == nil {
		return nil, ErrNoSAN
	}

	var values []asn1.RawValue

	err := asn1UnmarshalExactly(sanBytes, &values)
	if err != nil {
		return nil, err
	}

	for _, v := range values {
		if v.Tag == 4 && v.Class == asn1.ClassContextSpecific {
			var seq pkix.RDNSequence
			err = asn1UnmarshalExactly(v.Bytes, &seq)
			if err != nil {
				return nil, err
			}

			return deviceAttributesFromRDNSequence(seq)
		}
	}

	return nil, errors.New("RDNSequence not found within SAN GeneralNames")
}

var deviceManufacturerPattern = regexp.MustCompilePOSIX("^id:([0-9A-F]{8})$")

func getHwSerialNumFromEKCertificate(cert *x509.Certificate) (string, error) {
	deviceAttr, err := deviceAttributesFromEKCertificate(cert)
	if err != nil {
		return "", fmt.Errorf("could not read TPM device attributes from EK certificate: %w", err)
	}

	submatch := deviceManufacturerPattern.FindStringSubmatch(deviceAttr.Manufacturer)
	if submatch == nil {
		return "", fmt.Errorf("bad TPM manufacturer format: %s", deviceAttr.Manufacturer)
	}

	manufacturer := submatch[1]
	hwSerialNum := fmt.Sprintf("%s:%X:%X", manufacturer, cert.AuthorityKeyId, cert.SerialNumber.Bytes())
	return hwSerialNum, nil
}

// TODO[check]: it's not clear on the DevID spec which hash algorithm must be
// used. Assuming SHA256 for now given the value of the "assigner" field is
// "tcg-on-ekPermIdSha256".
var identifierValueHashAlgorithm = crypto.SHA256

func getPlatformIdentifierFromCertificate(cert *x509.Certificate) string {
	h := identifierValueHashAlgorithm.New()
	h.Write(cert.Raw)

	// TODO[check]: spec says "hexadecimal form using the UTF8 character set"
	// but doesn't specify if it's uppercase or lowercase (EK certificate hex
	// values are uppercase).
	return fmt.Sprintf("%X", h.Sum(nil))
}

func getPlatformIdentifierFromPublicKey(pub crypto.PublicKey) (string, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	h := identifierValueHashAlgorithm.New()
	h.Write([]byte("EkPubkey"))
	h.Write(keyBytes)

	// TODO[check]: same as mentioned at getPlatformIdentifierFromCertificate.
	return fmt.Sprintf("%X", h.Sum(nil)), nil
}

func DevIDSANFromEKCertificate(subjectIsEmpty bool, cert *x509.Certificate) (pkix.Extension, error) {
	hwSerialNum, err := getHwSerialNumFromEKCertificate(cert)
	if err != nil {
		return pkix.Extension{}, err
	}

	platformIdentifier := getPlatformIdentifierFromCertificate(cert)
	return buildSAN(subjectIsEmpty, []byte(hwSerialNum), platformIdentifier)
}

func DevIDSANFromEKPublicKey(subjectIsEmpty bool, pub crypto.PublicKey) (pkix.Extension, error) {
	platformIdentifier, err := getPlatformIdentifierFromPublicKey(pub)
	if err != nil {
		return pkix.Extension{}, err
	}

	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return pkix.Extension{}, err
	}

	// TODO[check]: check which hash algorithm should be used for hwSerialNum
	hwSerialNum := sha256.Sum256(keyBytes)

	return buildSAN(subjectIsEmpty, hwSerialNum[:], platformIdentifier)
}
