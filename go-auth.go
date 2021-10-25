package main

import "C"

import (
	"log"

	"github.com/sapcc/mosquitto/auth"
)

// errors to signal mosquitto
const (
	AuthRejected = 0
	AuthGranted  = 1
	AuthError    = 2
)

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
func AuthAclCheck(clientid, username, topic string, acc int) (result uint8) {
	access := auth.ACLAccess(acc)
	err := auth.CheckACL(username, topic, access)
	if err != nil {
		log.Printf("ACL reject %s. username: %s, topic: %s, err: %v", access, username, topic, err)
		return AuthRejected
	}
	//access is allowed
	Debugf("ACL allow %s. client: %s, username: %s, topic: %s", access, username, topic)
	return AuthGranted

}

//export AuthPskKeyGet
func AuthPskKeyGet() bool {
	return true
}

//export AuthPluginCleanup
func AuthPluginCleanup() {
	Debugf("AuthPluginCleanup")
}

func Debugf(msg string, args ...interface{}) {
	if debug {
		log.Printf(msg, args...)
	}
}

func main() {}
