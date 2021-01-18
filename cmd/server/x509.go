package main

import (
	"encoding/asn1"
	"time"
)

var (
	// http://oid-info.com/get/2.23.133
	oidTCG = asn1.ObjectIdentifier{2, 23, 133}

	// TPM 2.0 Keys for DevID, 8.2. TCG OIDs
	oidCapVerifiedTPMResidency  = append(oidTCG, 11, 1, 1)
	oidCapVerifiedTPMFixed      = append(oidTCG, 11, 1, 2)
	oidCapVerifiedTPMRestricted = append(oidTCG, 11, 1, 3)

	// TPM 2.0 Keys for DevID, 8.2. TCG OIDs
	oidHardwareTypeTPM2 = append(oidTCG, 1, 2)
)

var (
	// RFC 5280, 4.1.2.5. Validity
	// Used to indicate that the certificate has no well-defined expiration date.
	//
	// TODO: Check if Go is encoding this value properly as Generalized Time
	// "99991231235959Z"
	noExpirationDate = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)
