#include <stdio.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>

int mosquitto_auth_plugin_version(void) {
  return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
	printf("FABUS: mosquitto_auth_plugin_init\n");
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
	printf( "FABUS: mosquitto_auth_plugin_cleanup\n");
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
	printf("FABUS: mosquitto_auth_security_init\n");
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload){
	printf("FABUS: mosquitto_auth_security_cleanup\n");
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access) {
  printf("FABUS: mosquitto_auth_acl_check(clientid: %s, username: %s, topic: %s, access: %d)\n", clientid, username, topic, access);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password) {
	printf("FABUS: mosquitto_auth_unpwd_check(username: %s, password: %s)\n", username, password);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len) {
  return 1; 
}
