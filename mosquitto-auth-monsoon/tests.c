#include <stdlib.h>
#include <stdio.h>
#include "minunit.h"

#include "mosquitto_auth_plugin_monsoon.c"

#include <stdarg.h>
void mosquitto_log_printf(int level, const char *fmt, ...) {

	if (getenv("DEBUG") == NULL ) return;
  va_list va;

	va_start(va, fmt);
  vprintf(fmt, va);
  printf("\n");
  va_end(va);

}

int tests_run = 0;

static char *parse_subject() {

  const char *subject = "CN=blafasel,O=org,OU=ou";

  client_info *info = malloc(sizeof(client_info)); // this leaks but yolo
  int rc;

  rc = _parse_subject(subject, info);
  mu_assert("parsing valid subject failed", rc == 0);
  mu_assert("CN not set", info->common_name );
  mu_assert("CN not correct", strcmp(info->common_name, "blafasel") == 0);
  mu_assert("O not set", info->organization );
  mu_assert("O not correct", strcmp(info->organization, "org") == 0);
  mu_assert("OU not set", info->organizational_unit );
  mu_assert("OU not correct", strcmp(info->organizational_unit, "ou") == 0);
  return 0;
}

static char * empty_acl()  {
  
  const char *username = "CN=blafasel,O=org,OU=ou";
  auth_db *db = _malloc_auth_db(); // this leaks but yolo

  int rc;
  rc = mosquitto_auth_acl_check(db, username, username, "sometopic", MOSQ_ACL_READ);
  mu_assert("Access denied", rc == MOSQ_ERR_SUCCESS);
  return 0;
}

static char * user_acl()  {
  
  const char *user = "CN=blafasel,O=org,OU=ou";
  int rc;

  auth_db *db = _malloc_auth_db(); // this leaks but yolo
	rc = _add_acl(db, "CN=blafasel", "sometopic", MOSQ_ACL_READ);
	mu_assert("Invalid ACL", rc == 0);

  rc = mosquitto_auth_acl_check(db, user, user, "sometopic", MOSQ_ACL_READ);
  mu_assert("Access denied for matching acl", rc == MOSQ_ERR_SUCCESS);

  rc = mosquitto_auth_acl_check(db, user, user, "sometopic", MOSQ_ACL_WRITE);
  mu_assert("Access granted for wrong access mode", rc == MOSQ_ERR_ACL_DENIED);

  rc = mosquitto_auth_acl_check(db, user, user, "anothertopic", MOSQ_ACL_READ);
  mu_assert("Access granted for wrong topic", rc == MOSQ_ERR_ACL_DENIED);


  rc = mosquitto_auth_acl_check(db, "", "CN=user,O=org,OU=ou", "anothertopic", MOSQ_ACL_READ);
  mu_assert("Access granted for user2", rc == MOSQ_ERR_ACL_DENIED);


	rc = _add_acl(db, "O=org", "sometopic", MOSQ_ACL_READ);
	mu_assert("Invalid ACL", rc == 0);
  rc = mosquitto_auth_acl_check(db, "", "CN=user,O=org,OU=ou", "sometopic", MOSQ_ACL_READ);
  mu_assert("Access denied for user with O=org", rc == MOSQ_ERR_SUCCESS);



  return 0;
}


static char * all_tests() {
  mu_run_test(parse_subject);
  mu_run_test(empty_acl);
  mu_run_test(user_acl);
  return 0;
}

int main(int argc, char **argv) {
  char *result = all_tests();
  if (result != 0) {
    printf("%s\n", result);
  }
  else {
    printf("ALL TESTS PASSED\n");
  }
  printf("Tests run: %d\n", tests_run);
 
  return result != 0;
}
