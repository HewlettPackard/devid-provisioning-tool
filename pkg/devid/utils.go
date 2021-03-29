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
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type KeyError struct {
	Reason string
}

func (e KeyError) Error() string {
	return fmt.Sprintf("key error: %s", e.Reason)
}

var (
	ErrNotSigningKey = KeyError{Reason: "not a signing key"}
	ErrBadKeyFormat  = KeyError{Reason: "malformed key"}
)

func GetSignatureScheme(pub tpm2.Public) (*tpm2.SigScheme, error) {
	canSign := (pub.Attributes & tpm2.FlagSign) == tpm2.FlagSign
	if !canSign {
		return nil, ErrNotSigningKey
	}

	switch pub.Type {
	case tpm2.AlgRSA:
		params := pub.RSAParameters
		if params == nil {
			return nil, ErrBadKeyFormat
		}

		return params.Sign, nil

	case tpm2.AlgECDSA:
		params := pub.ECCParameters
		if params == nil {
			return nil, ErrBadKeyFormat
		}

		return params.Sign, nil

	default:
		return nil, KeyError{Reason: fmt.Sprintf("unsupported key type 0x%04x", pub.Type)}
	}
}

func getSignature(sig *tpm2.Signature) ([]byte, error) {
	switch sig.Alg {
	case tpm2.AlgRSASSA, tpm2.AlgRSAPSS:
		return sig.RSA.Signature, nil

	case tpm2.AlgECDSA:
		var b cryptobyte.Builder
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1BigInt(sig.ECC.R)
			b.AddASN1BigInt(sig.ECC.S)
		})

		return b.Bytes()

	default:
		return nil, fmt.Errorf("bad signature algorithm: 0x%04x", sig.Alg)
	}
}

func hash(rw io.ReadWriter, hierarchy tpmutil.Handle, hashAlg tpm2.Algorithm, data []byte) ([]byte, *tpm2.Ticket, error) {
	const (
		maxDigestBuffer = 1024
		seqAuth         = ""
	)

	if len(data) <= maxDigestBuffer {
		digest, validation, err := tpm2.Hash(rw, hashAlg, data, hierarchy)
		if err != nil {
			err = fmt.Errorf("tpm2.Hash failed: %w", err)
			return nil, nil, err
		}

		return digest, validation, nil
	}

	seq, err := tpm2.HashSequenceStart(rw, seqAuth, hashAlg)
	if err != nil {
		err = fmt.Errorf("tpm2.HashSequenceStart failed: %w", err)
		return nil, nil, err
	}

	defer tpm2.FlushContext(rw, seq)

	for len(data) > maxDigestBuffer {
		err = tpm2.SequenceUpdate(rw, seqAuth, seq, data[:maxDigestBuffer])
		if err != nil {
			err = fmt.Errorf("tpm2.SequenceUpdate failed: %w", err)
			return nil, nil, err
		}

		data = data[maxDigestBuffer:]
	}

	digest, validation, err := tpm2.SequenceComplete(rw, seqAuth, seq, hierarchy, data)
	if err != nil {
		err = fmt.Errorf("tpm2.SequenceComplete failed: %w", err)
		return nil, nil, err
	}

	return digest, validation, nil
}

func HashAndSign(
	rw io.ReadWriter,
	hierarchy tpmutil.Handle,
	keyHandle tpmutil.Handle,
	data []byte,
) ([]byte, error) {
	pub, _, _, err := tpm2.ReadPublic(rw, keyHandle)
	if err != nil {
		err = fmt.Errorf("tpm2.ReadPublic failed: %w", err)
		return nil, err
	}

	sigScheme, err := GetSignatureScheme(pub)
	if err != nil {
		return nil, err
	}

	digest, token, err := hash(rw, hierarchy, sigScheme.Hash, data)
	if err != nil {
		return nil, err
	}

	sig, err := tpm2.Sign(rw, keyHandle, "", digest, token, sigScheme)
	if err != nil {
		err = fmt.Errorf("tpm2.Sign failed: %w", err)
		return nil, err
	}

	return getSignature(sig)
}
