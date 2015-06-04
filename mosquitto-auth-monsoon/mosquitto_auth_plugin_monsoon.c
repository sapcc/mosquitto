#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <ldap.h>

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
  LDAPDN dn = NULL;
  int err = ldap_str2dn(username, &dn , LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PEDANTIC);
  if (err != 0) {
    printf("FABUS: error parsing dn: %d)\n", err);
    ldap_dnfree(dn);
    return MOSQ_ERR_ACL_DENIED;
  }
  LDAPAVA *attr = NULL;
  LDAPRDN rdn = NULL;
  char* common_name = NULL;
  char* organizational_unit = NULL; 
  char* organization = NULL;
  /* iterate over DN components: e.g. cn=a+sn=b */
  int idx;
	for (idx = 0; dn[idx] != NULL; idx++) {
    rdn = dn[idx];
    attr = rdn[0];
    if ((attr->la_flags & LDAP_AVA_STRING) == 0) {
      //skip non string attributes
      continue;
    }
    if (attr->la_attr.bv_len == 2 && strncasecmp("CN", attr->la_attr.bv_val, 2) == 0) {
          common_name = strdup(attr->la_value.bv_val);
          printf("Common Name: %s\n", common_name);
    }
    if (attr->la_attr.bv_len == 2 && strncasecmp("OU", attr->la_attr.bv_val, 2) == 0) {
          organizational_unit = strdup(attr->la_value.bv_val);
          printf("Organizational Unit: %s\n", organizational_unit);
    }
    if (attr->la_attr.bv_len == 1 && strncasecmp("O", attr->la_attr.bv_val, 1) == 0) {
          organization = strdup(attr->la_value.bv_val);
          printf("Organization: %s\n", organization);
    }
  }
  if (common_name) free(common_name);
  if (organizational_unit) free(organizational_unit);
  if (organization) free(organization);
  ldap_dnfree(dn);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password) {
	printf("FABUS: mosquitto_auth_unpwd_check(username: %s, password: %s)\n", username, password);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len) {
  return 1; 
}
