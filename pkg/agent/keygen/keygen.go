package keygen

import (
	"io"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func DefaultRSA() *Keygen {
	return &Keygen{
		config: config{
			ekTemplate:        tpm2tools.DefaultEKTemplateRSA(),
			srkTemplate:       tpm2tools.SRKTemplateRSA(),
			akTemplate:        DefaultAKTemplateRSA(),
			devIDTemplate:     DefaultDevIDTemplateRSA(),
			createPrimaryKeys: false,
		},
	}
}

type KeyInfo struct {
	Handle      tpmutil.Handle
	Template    tpm2.Public
	Public      tpm2.Public
	PublicBlob  []byte
	PrivateBlob []byte
}

type Keygen struct {
	config
}

func New(opts ...Option) *Keygen {
	gen := DefaultRSA()

	for _, opt := range opts {
		opt(&gen.config)
	}

	return gen
}

func (gen *Keygen) CreateEndorsementKey(rw io.ReadWriter) (*KeyInfo, error) {
	return newCachedKey(
		rw,
		gen.ekTemplate,
		tpm2.HandleOwner,
		tpm2.HandleEndorsement,
		tpm2tools.EKReservedHandle,
	)
}

func (gen *Keygen) CreateAttestationKey(rw io.ReadWriter) (*KeyInfo, error) {
	return gen.createGenericKey(rw, gen.akTemplate)
}

func (gen *Keygen) CreateDevIDKey(rw io.ReadWriter) (*KeyInfo, error) {
	return gen.createGenericKey(rw, gen.devIDTemplate)
}

func (gen *Keygen) createGenericKey(rw io.ReadWriter, template tpm2.Public) (*KeyInfo, error) {
	if gen.createPrimaryKeys {
		return createPrimaryKey(rw, tpm2.HandleEndorsement, template)
	}

	srk, err := gen.createSRK(rw)
	if err != nil {
		return nil, err
	}

	defer tpm2.FlushContext(rw, srk.Handle)

	return createLoadedKey(rw, srk.Handle, template)
}

func (gen *Keygen) createSRK(rw io.ReadWriter) (*KeyInfo, error) {
	return newCachedKey(
		rw,
		gen.srkTemplate,
		tpm2.HandleOwner,
		tpm2.HandleOwner,
		tpm2tools.SRKReservedHandle,
	)
}
