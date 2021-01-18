package keygen

import (
	"github.com/google/go-tpm/tpm2"
)

const (
	FlagAttestationKeyDefault = tpm2.FlagSign |
		tpm2.FlagRestricted |
		tpm2.FlagFixedTPM |
		tpm2.FlagFixedParent |
		tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagUserWithAuth

	FlagDevIDKeyDefault = tpm2.FlagSign |
		tpm2.FlagFixedTPM |
		tpm2.FlagFixedParent |
		tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagUserWithAuth
)

func DefaultAKTemplateRSA() tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: FlagAttestationKeyDefault,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256), // Use public.unique to generate distinct keys
		},
	}
}

func DefaultDevIDTemplateRSA() tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: FlagDevIDKeyDefault,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256), // Use public.unique to generate distinct keys
		},
	}
}
