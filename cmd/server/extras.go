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
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/HewlettPackard/devid-provisioning-tool/pkg/devid"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
)

type KeyAttributeError struct {
	Reason string
}

func (e KeyAttributeError) Error() string {
	return fmt.Sprintf("key attribute error: %s", e.Reason)
}

func checkDevIDProp(prop tpm2.KeyProp) error {
	if (prop & tpm2.FlagDecrypt) != 0 {
		return KeyAttributeError{
			Reason: "DevID should not be a decryption key",
		}
	}

	if (prop & tpm2.FlagRestricted) != 0 {
		return KeyAttributeError{
			Reason: "DevID should not be a restricted key",
		}
	}

	if (prop & tpm2.FlagSign) == 0 {
		return KeyAttributeError{
			Reason: "DevID should be a signing key",
		}
	}

	if (prop & tpm2.FlagFixedTPM) == 0 {
		return KeyAttributeError{
			Reason: "DevID should be fixedTPM",
		}
	}

	return nil
}

func checkAKProp(prop tpm2.KeyProp) error {
	if (prop & tpm2.FlagDecrypt) != 0 {
		return KeyAttributeError{
			Reason: "AK should not be a decryption key",
		}
	}

	if (prop & tpm2.FlagRestricted) == 0 {
		return KeyAttributeError{
			Reason: "AK should be a restricted key",
		}
	}

	if (prop & tpm2.FlagSign) == 0 {
		return KeyAttributeError{
			Reason: "AK should be a signing key",
		}
	}

	if (prop & tpm2.FlagFixedTPM) == 0 {
		return KeyAttributeError{
			Reason: "AK should be fixedTPM",
		}
	}

	return nil
}

func createChallenge(encPub *tpm2.Public, credName tpm2.Name) (credentialBlob, secret, nonce []byte, err error) {
	hash, err := encPub.NameAlg.Hash()
	if err != nil {
		return nil, nil, nil, err
	}

	nonce = make([]byte, hash.Size())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, nil, err
	}

	encKey, err := encPub.Key()
	if err != nil {
		return nil, nil, nil, err
	}

	var symBlockSize int
	switch encKey.(type) {
	case *rsa.PublicKey:
		symBlockSize = int(encPub.RSAParameters.Symmetric.KeyBits) / 8

	default:
		return nil, nil, nil, errors.New("unsupported algorithm")
	}

	credentialBlob, secret, err = credactivation.Generate(
		credName.Digest,
		encKey,
		symBlockSize,
		nonce,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	return credentialBlob[2:], secret[2:], nonce, err
}

func checkSignature(pub *tpm2.Public, data, sig []byte) error {
	key, err := pub.Key()
	if err != nil {
		return err
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("only RSA keys are supported")
	}

	sigScheme, err := devid.GetSignatureScheme(*pub)
	if err != nil {
		return err
	}

	hash, err := sigScheme.Hash.Hash()
	if err != nil {
		return err
	}

	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(rsaKey, hash, hashed, sig)
}
