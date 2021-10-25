package auth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestACLCheck(t *testing.T) {

	cases := []struct {
		Username      string
		Topic         string
		Access        ACLAccess
		Allow         bool
		ErrorContains string
	}{
		{
			Username:      "client1",
			Topic:         "some/topic",
			Access:        ACLAccessRead,
			Allow:         false,
			ErrorContains: "Error parsing username",
		},
		{
			Username:      "CN=client1,O=org1",
			Topic:         "some/topic",
			Access:        ACLAccessRead,
			Allow:         false,
			ErrorContains: "does not contain exactly one O and OU field",
		},
		{
			Username: "CN=client1,O=org1,OU=team1",
			Topic:    "identity/client1",
			Access:   ACLAccessRead,
			Allow:    true,
		},
		{
			Username: "CN=client1,O=org1,OU=team1",
			Topic:    "identity/client2",
			Access:   ACLAccessRead,
			Allow:    false,
		},
		{
			Username: "CN=client1,O=org1,OU=team1",
			Topic:    "reply/some-topic",
			Access:   ACLAccessWrite,
			Allow:    true,
		},
		{
			Username: "CN=client1,O=org1,OU=team1",
			Topic:    "reply/some-topic",
			Access:   ACLAccessRead,
			Allow:    false,
		},
		{
			Username: "CN=client1,O=org1,OU=team1",
			Topic:    "registration/org1/team1/client1",
			Access:   ACLAccessWrite,
			Allow:    true,
		},
		{
			Username: "CN=client1,O=org1,OU=team1",
			Topic:    "registration/org2/team1/client1",
			Access:   ACLAccessWrite,
			Allow:    false,
		},
		{
			Username: "CN=client1,O=org1,OU=team1",
			Topic:    "registration/org1/team2/client1",
			Access:   ACLAccessWrite,
			Allow:    false,
		},
		{
			Username: "CN=client1,O=org1,OU=team1",
			Topic:    "registration/org1/team1/client2",
			Access:   ACLAccessWrite,
			Allow:    false,
		},
	}

	for n, c := range cases {
		err := CheckACL(c.Username, c.Topic, c.Access)
		finfo := fmt.Sprintf("Test case %d failed, username: %s, topic: %s, access: %s", n+1, c.Username, c.Topic, c.Access)
		if c.Allow {
			assert.NoError(t, err, finfo)
		} else {
			assert.Error(t, err, finfo)
		}
		if c.ErrorContains != "" {
			assert.Contains(t, err.Error(), c.ErrorContains, finfo)
		}
	}

}
