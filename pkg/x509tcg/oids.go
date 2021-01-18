package x509tcg

import "encoding/asn1"

var (
	// RFC 5280, 4.2.1. Standard Extensions
	oidCertificateExtension = asn1.ObjectIdentifier{2, 5, 29}

	// RFC 5280, 4.2.1.6. Subject Alternative Name
	oidSubjectAltName = oidExtend(oidCertificateExtension, 17)

	oidOn                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8}
	oidOnHardwareModuleName  = oidExtend(oidOn, 4)
	oidOnPermanentIdentifier = oidExtend(oidOn, 3)
)

var (
	oidTCG = asn1.ObjectIdentifier{2, 23, 133}

	oidTCGSpecVersion      = oidExtend(oidTCG, 1)
	oidTCGHardwareTypeTPM2 = oidExtend(oidTCGSpecVersion, 2)

	oidTCGAttribute                = oidExtend(oidTCG, 2)
	oidTCGAttributeTPMManufacturer = oidExtend(oidTCGAttribute, 1)
	oidTCGAttributeTPMModel        = oidExtend(oidTCGAttribute, 2)
	oidTCGAttributeTPMVersion      = oidExtend(oidTCGAttribute, 3)

	oidTCGOnEKPermIDSha256 = oidExtend(oidTCG, 12, 1)
)

func oidExtend(base asn1.ObjectIdentifier, ids ...int) asn1.ObjectIdentifier {
	oid := make(asn1.ObjectIdentifier, len(base)+len(ids))
	copy(oid[:len(base)], base)
	copy(oid[len(base):], ids)
	return oid
}
