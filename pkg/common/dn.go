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
