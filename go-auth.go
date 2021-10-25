package main

import "C"

import (
	"crypto/x509/pkix"
	"fmt"
	"log"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

// errors to signal mosquitto
const (
	AuthRejected = 0
	AuthGranted  = 1
	AuthError    = 2
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

var debug = false

//export AuthPluginInit
func AuthPluginInit(keys []string, values []string, authOptsNum int, version string) {
	for i := 0; i < authOptsNum; i++ {
		key, value := keys[i], values[i]
		switch key {
		case "debug":
			debug = value == "true"
		}
	}
}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username, password, clientid string) uint8 {
	Debugf("AuthUnpwdCheck(username: %s, password: ***, clientid: %s)", username, clientid)
	return AuthGranted
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic string, acc ACLAccess) (result uint8) {
	defer func() {
		Debugf("ACL %s %s. client: %s, username: %s, topic: %s", aclResultString(result), acc, clientid, username, topic)
	}()
	dn, err := parseDN(username)
	if err != nil {
		log.Printf("ACL reject %s. Error parsing username %s as dn: %v", acc, username, err)
		return AuthRejected
	}

	if len(dn.Organization) != 1 || len(dn.OrganizationalUnit) != 1 {
		log.Printf("ACL reject %s. Parsed username %s does not contain exactly one o and ou field", acc, username)
		return AuthRejected
	}
	var organization, unit = dn.Organization[0], dn.OrganizationalUnit[0]

	// arc-api can do anything
	if organization == "arc-api" && unit == "arc-api" {
		return AuthGranted
	}
	//agent acl check
	switch acc {
	case ACLAccessRead:
		if topic == "identity/"+dn.CommonName {
			return AuthGranted
		}
	case ACLAccessWrite:
		if topic == "registration/"+organization+"/"+unit+"/"+dn.CommonName {
			return AuthGranted
		}
		if strings.HasPrefix(topic, "reply/") {
			return AuthGranted
		}
	case ACLAccessSubscribe:
		if topic == "identity/"+dn.CommonName {
			return AuthGranted
		}
	}
	log.Printf("ACL reject %s. client: %s, username: %s, topic: %s", acc, clientid, username, topic)
	return AuthRejected
}

//export AuthPskKeyGet
func AuthPskKeyGet() bool {
	return true
}

//export AuthPluginCleanup
func AuthPluginCleanup() {
	log.Println("AuthPluginCleanup")
}

func Debugf(msg string, args ...interface{}) {
	if debug {
		log.Printf(msg, args...)
	}
}

func parseDN(dn string) (*pkix.Name, error) {
	d, err := ldap.ParseDN(dn)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse dn: %w", err)
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

func aclResultString(result uint8) string {
	switch result {
	case AuthRejected:
		return "reject"
	case AuthGranted:
		return "allow"
	case AuthError:
		return "error"
	}
	return fmt.Sprintf("unknown (%d)", result)
}

func main() {}
