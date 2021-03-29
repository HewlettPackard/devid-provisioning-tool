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
package common

import "crypto/x509/pkix"

type DistinguishedName struct {
	Country            []string `hcl:"country,optional"`
	Organization       []string `hcl:"organization,optional"`
	OrganizationalUnit []string `hcl:"organizational_unit,optional"`
	Locality           []string `hcl:"locality,optional"`
	Province           []string `hcl:"province,optional"`
	StreetAddress      []string `hcl:"street_address,optional"`
	PostalCode         []string `hcl:"postal_code,optional"`
}

func (dn *DistinguishedName) AppendInto(n *pkix.Name) {
	if dn == nil {
		return
	}

	n.Country = append(n.Country, dn.Country...)
	n.Organization = append(n.Organization, dn.Organization...)
	n.OrganizationalUnit = append(n.OrganizationalUnit, dn.OrganizationalUnit...)
	n.Locality = append(n.Locality, dn.Locality...)
	n.Province = append(n.Province, dn.Province...)
	n.StreetAddress = append(n.StreetAddress, dn.StreetAddress...)
	n.PostalCode = append(n.PostalCode, dn.PostalCode...)
}
