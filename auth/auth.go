package auth

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

type ACLAccess int

const (
	ACLAceessNone        ACLAccess = 0
	ACLAccessRead        ACLAccess = 1
	ACLAccessWrite       ACLAccess = 2
	ACLAccessSubscribe   ACLAccess = 4
	ACLAccessUnsubscribe ACLAccess = 8
)

func (a ACLAccess) String() string {
	switch a {
	case ACLAccessRead:
		return "read"
	case ACLAccessWrite:
		return "write"
	case ACLAccessSubscribe:
		return "subscribe"
	case ACLAccessUnsubscribe:
		return "unsubscribe"
	}
	return fmt.Sprintf("unknown (%d)", a)
}

func CheckACL(username, topic string, access ACLAccess) error {

	dn, err := parseDN(username)
	if err != nil {
		return fmt.Errorf("Error parsing username %s as dn: %w", username, err)
	}

	if len(dn.Organization) != 1 || len(dn.OrganizationalUnit) != 1 {
		return fmt.Errorf("Username %s does not contain exactly one O and OU field", username)
	}
	var organization, unit = dn.Organization[0], dn.OrganizationalUnit[0]

	// arc-api can do anything
	if organization == "arc-api" && unit == "arc-api" {
		return nil
	}
	//agent acl check
	switch access {
	case ACLAccessRead:
		if topic == "identity/"+dn.CommonName {
			return nil
		}
	case ACLAccessWrite:
		if topic == "registration/"+organization+"/"+unit+"/"+dn.CommonName {
			return nil
		}
		if strings.HasPrefix(topic, "reply/") {
			return nil
		}
	case ACLAccessSubscribe:
		if topic == "identity/"+dn.CommonName {
			return nil
		}
	}
	return errors.New("Not allowed")

}

func parseDN(dn string) (*pkix.Name, error) {
	d, err := ldap.ParseDN(dn)
	if err != nil {
		return nil, err
	}
	var name pkix.Name
	for _, r := range d.RDNs {
		for _, a := range r.Attributes {
			switch a.Type {
			case "CN", "cn":
				name.CommonName = a.Value
			case "O", "o":
				name.Organization = append(name.Organization, a.Value)
			case "OU", "ou":
				name.OrganizationalUnit = append(name.OrganizationalUnit, a.Value)
			case "L", "l":
				name.Locality = append(name.Locality, a.Value)
			case "C", "c":
				name.Country = append(name.Country, a.Value)
			case "ST", "st":
				name.Province = append(name.Province, a.Value)
			case "STREET", "street":
				name.StreetAddress = append(name.StreetAddress, a.Value)
			}
		}
	}
	return &name, nil
}
