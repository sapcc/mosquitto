#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

#include "go-auth.h"

// Same constant as one in go-auth.go.
#define AuthRejected 0
#define AuthGranted 1
#define AuthError 2

static mosquitto_plugin_id_t *mosq_pid = NULL;

int acl_check_callback(int event, void *event_data, void *user_data);

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions) {
  return MOSQ_PLUGIN_VERSION;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata, struct mosquitto_opt *options, int option_count) {
  mosq_pid = identifier;
  //  Pass plugin_opts hash as keys and values char* arrays to Go in order to initialize them there.

  GoString keys[option_count];
  GoString values[option_count];
  int i;
  struct mosquitto_opt *o;
  for (i = 0, o = options; i < option_count; i++, o++) {
    GoString opt_key = {o->key, strlen(o->key)};
    GoString opt_value = {o->value, strlen(o->value)};
    keys[i] = opt_key;
    values[i] = opt_value;
  }

  GoSlice keysSlice = {keys, option_count, option_count};
  GoSlice valuesSlice = {values, option_count, option_count};

  char versionArray[10];
  sprintf(versionArray, "%i.%i.%i", LIBMOSQUITTO_MAJOR, LIBMOSQUITTO_MINOR, LIBMOSQUITTO_REVISION);

  GoString version = {versionArray, strlen(versionArray)};
  GoInt32 opts_count = option_count;
  AuthPluginInit(keysSlice, valuesSlice, opts_count, version);

  mosquitto_callback_register(mosq_pid, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL, NULL);
  return 0;
}

int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count) {

	return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL);
}

int acl_check_callback(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_acl_check *ed = event_data;

  const char* clientid = mosquitto_client_id(ed->client);
  const char* username = mosquitto_client_username(ed->client);
  const char* topic = ed->topic;

  GoString go_clientid = {clientid, strlen(clientid)};
  GoString go_username = {username, strlen(username)};
  GoString go_topic = {topic, strlen(topic)};
  GoInt32 go_access = ed->access;

  GoUint8 ret = AuthAclCheck(go_clientid, go_username, go_topic, go_access);

  switch (ret)
  {
  case AuthGranted:
    return MOSQ_ERR_SUCCESS;
    break;
  case AuthRejected:
    return MOSQ_ERR_ACL_DENIED;
    break;
  case AuthError:
    return MOSQ_ERR_UNKNOWN;
    break;
  default:
    mosquitto_log_printf(MOSQ_LOG_ERR, "unknown plugin error: %d\n", ret);
    return MOSQ_ERR_UNKNOWN;
  }

	return MOSQ_ERR_SUCCESS;
}

