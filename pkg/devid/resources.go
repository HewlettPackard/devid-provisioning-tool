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
package devid

import (
	"io"

	"github.com/HewlettPackard/devid-provisioning-tool/pkg/agent/keygen"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type RequestResources struct {
	Attestation *keygen.KeyInfo
	Endorsement *keygen.KeyInfo
	DevID       *keygen.KeyInfo

	rw io.ReadWriter
}

func (rh *RequestResources) Flush() {
	if rh.Attestation != nil && rh.Attestation.Handle != 0 {
		tpm2.FlushContext(rh.rw, rh.Attestation.Handle)
		rh.Attestation.Handle = 0
	}

	if rh.Endorsement != nil && rh.Endorsement.Handle != 0 {
		tpm2.FlushContext(rh.rw, rh.Endorsement.Handle)
		rh.Endorsement.Handle = 0
	}

	if rh.DevID != nil && rh.DevID.Handle != 0 {
		tpm2.FlushContext(rh.rw, rh.DevID.Handle)
		rh.DevID.Handle = 0
	}
}

func (rh *RequestResources) Activate(credentialBlob, secret []byte) ([]byte, error) {
	hSession, err := createPolicySession(rh.rw)
	if err != nil {
		return nil, err
	}

	defer tpm2.FlushContext(rh.rw, hSession)

	return tpm2.ActivateCredentialUsingAuth(
		rh.rw,
		[]tpm2.AuthCommand{
			{Session: tpm2.HandlePasswordSession},
			{Session: hSession},
		},
		rh.Attestation.Handle,
		rh.Endorsement.Handle,
		credentialBlob,
		secret,
	)
}

func createPolicySession(rw io.ReadWriter) (tpmutil.Handle, error) {
	var nonceCaller [32]byte
	hSession, _, err := tpm2.StartAuthSession(
		rw,
		tpm2.HandleNull,
		tpm2.HandleNull,
		nonceCaller[:],
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256,
	)
	if err != nil {
		return 0, err
	}

	_, err = tpm2.PolicySecret(
		rw,
		tpm2.HandleEndorsement,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession},
		hSession,
		nil,
		nil,
		nil,
		0,
	)
	if err != nil {
		tpm2.FlushContext(rw, hSession)
		return 0, err
	}

	return hSession, nil
}
