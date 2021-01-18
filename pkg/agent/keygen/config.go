package keygen

import (
	"github.com/google/go-tpm/tpm2"
)

type config struct {
	ekTemplate        tpm2.Public
	akTemplate        tpm2.Public
	devIDTemplate     tpm2.Public
	srkTemplate       tpm2.Public
	createPrimaryKeys bool
}

type Option func(*config)

func UseSRKTemplate(template tpm2.Public) Option {
	return func(cfg *config) {
		cfg.srkTemplate = template
	}
}

func UseAKTemplate(template tpm2.Public) Option {
	return func(cfg *config) {
		cfg.akTemplate = template
	}
}

func UseDevIDTemplate(template tpm2.Public) Option {
	return func(cfg *config) {
		cfg.devIDTemplate = template
	}
}

func CreatePrimaryKeys(b bool) Option {
	return func(cfg *config) {
		cfg.createPrimaryKeys = b
	}
}
