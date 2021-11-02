package main

// #include <stdlib.h>
// #include <mosquitto_broker.h>
// #cgo LDFLAGS: -shared
// #cgo CFLAGS: -fPIC
//
// static void mosquitto_log(int lvl, char* s) {
//   mosquitto_log_printf(lvl, s);
// }
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/sapcc/mosquitto/auth"
)

// errors to signal mosquitto
const (
	AuthRejected = 0
	AuthGranted  = 1
	AuthError    = 2
)

//export AuthPluginInit
func AuthPluginInit(keys []string, values []string, authOptsNum int, version string) {
	log(LogInfo, "auth plugin init")
	for i := 0; i < authOptsNum; i++ {
		key, value := keys[i], values[i]
		switch key {
		case "debug":
			_ = value
		}
	}
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic string, acc int) (result uint8) {
	access := auth.ACLAccess(acc)

	err := auth.CheckACL(username, topic, access)
	if err != nil {
		log(LogNotice, "ACL reject %s. username: %s, topic: %s, err: %v", access, username, topic, err)
		return AuthRejected
	}
	//access is allowed
	log(LogDebug, "ACL allow %s. client: %s, username: %s, topic: %s", access, username, topic)
	return AuthGranted

}

type LogLevel int

const (
	LogInfo    LogLevel = 0x01
	LogNotice  LogLevel = 0x02
	LogWarning LogLevel = 0x04
	LogError   LogLevel = 0x08
	LogDebug   LogLevel = 0x10
)

func log(level LogLevel, msg string, args ...interface{}) {
	cmsg := C.CString(fmt.Sprintf(msg, args...))
	C.mosquitto_log(C.int(level), cmsg)
	C.free(unsafe.Pointer(cmsg))
}

func main() {}
