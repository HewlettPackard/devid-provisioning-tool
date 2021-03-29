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
