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
