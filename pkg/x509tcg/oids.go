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
