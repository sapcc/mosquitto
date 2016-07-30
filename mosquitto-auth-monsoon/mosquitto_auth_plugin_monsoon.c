#include <stdio.h>
#include <stdlib.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <ldap.h>

typedef struct {
  char subject[256];
  char *common_name;
  char *organization;
  char *organizational_unit;
} client_info;

struct _mosquitto_acl{
  struct _mosquitto_acl *next;
  char *topic;
  int access;
  int icount; // client id
  int ccount; // common_name
  int ucount; // organization unit
  int ocount; // organization
};

struct auth_db{
  struct _mosquitto_acl *acl_patterns;
  char * acl_file;
};

int _parse_subject(const char *subject, client_info *info) {
  LDAPDN dn = NULL;
  int err = ldap_str2dn(subject, &dn , LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PEDANTIC);
  if (err != 0) {
    printf("FABUS: error parsing dn: %d)\n", err);
    ldap_dnfree(dn);
    return -1; 
  }
  LDAPAVA *attr = NULL;
  LDAPRDN rdn = NULL;
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
      info->common_name = strdup(attr->la_value.bv_val);
    }
    if (attr->la_attr.bv_len == 2 && strncasecmp("OU", attr->la_attr.bv_val, 2) == 0) {
      info->organizational_unit = strdup(attr->la_value.bv_val);
    }
    if (attr->la_attr.bv_len == 1 && strncasecmp("O", attr->la_attr.bv_val, 1) == 0) {
      info->organization = strdup(attr->la_value.bv_val);
    }
  }
  ldap_dnfree(dn);
  return 0;
}

int _add_acl_pattern(struct auth_db *db, const char *topic, int access)
{
  struct _mosquitto_acl *acl, *acl_tail;
  char *local_topic;
  char *s;

  if(!db || !topic) return MOSQ_ERR_INVAL;

  local_topic = strdup(topic);
  if(!local_topic){
    return MOSQ_ERR_NOMEM;
  }

  acl = malloc(sizeof(struct _mosquitto_acl));
  if(!acl){
    free(local_topic);
    return MOSQ_ERR_NOMEM;
  }
  acl->access = access;
  acl->topic = local_topic;
  acl->next = NULL;

  // client id
  acl->icount = 0;
  s = local_topic;
  while(s){
    s = strstr(s, "%i");
    if(s){
      acl->icount++;
      s+=2;
    }
  }

  // common_name
  acl->ccount = 0;
  s = local_topic;
  while(s){
    s = strstr(s, "%c");
    if(s){
      acl->ccount++;
      s+=2;
    }
  }

  // organizational unit
  acl->ucount = 0;
  s = local_topic;
  while(s){
    s = strstr(s, "%u");
    if(s){
      acl->ucount++;
      s+=2;
    }
  }

  // organization
  acl->ocount = 0;
  s = local_topic;
  while(s){
    s = strstr(s, "%o");
    if(s){
      acl->ocount++;
      s+=2;
    }
  }

  if(db->acl_patterns){
    acl_tail = db->acl_patterns;
    while(acl_tail->next){
      acl_tail = acl_tail->next;
    }
    acl_tail->next = acl;
  }else{
    db->acl_patterns = acl;
  }

  return MOSQ_ERR_SUCCESS;
}


static int _aclfile_parse(struct auth_db *db, const char *filepath)
{
  FILE *aclfile;
  char buf[1024];
  char *token;
  char *topic;
  char *access_s;
  int access;
  int rc;
  int slen;
  char *saveptr = NULL;

  aclfile = fopen(filepath, "rt");
  if(!aclfile){
    //mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Unable to open acl_file \"%s\".", filepath);
    printf("Error: Unable to open acl_file \"%s\".", filepath);
    return 1;
  }

  // pattern [read|write] <topic> 
  while(fgets(buf, 1024, aclfile)){
    slen = strlen(buf);
    while(slen > 0 && (buf[slen-1] == 10 || buf[slen-1] == 13)){
      buf[slen-1] = '\0';
      slen = strlen(buf);
    }
    if(buf[0] == '#'){
      continue;
    }
    token = strtok_r(buf, " ", &saveptr);
    if(token){
      if(!strcmp(token, "pattern")){

        access_s = strtok_r(NULL, " ", &saveptr);
        if(!access_s){
          //mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Empty topic in acl_file.");
          printf("Error: Empty topic in acl_file.\n");
          fclose(aclfile);
          return MOSQ_ERR_INVAL;
        }
        token = strtok_r(NULL, "", &saveptr);
        if(token){
          topic = token;
          /* Ignore duplicate spaces */
          while(topic[0] == ' '){
            topic++;
          }
        }else{
          topic = access_s;
          access_s = NULL;
        }
        if(access_s){
          if(!strcmp(access_s, "read")){
            access = MOSQ_ACL_READ;
          }else if(!strcmp(access_s, "write")){
            access = MOSQ_ACL_WRITE;
          }else if(!strcmp(access_s, "readwrite")){
            access = MOSQ_ACL_READ | MOSQ_ACL_WRITE;
          }else{
            //mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Invalid topic access type \"%s\" in acl_file.", access_s);
            printf("Error: Invalid topic access type \"%s\" in acl_file.\n", access_s);
            fclose(aclfile);
            return MOSQ_ERR_INVAL;
          }
        }else{
          access = MOSQ_ACL_READ | MOSQ_ACL_WRITE;
        }
        rc = _add_acl_pattern(db, topic, access);
        if(rc){
          fclose(aclfile);
          return rc;
        }
      }
    }
  }

  fclose(aclfile);

  return MOSQ_ERR_SUCCESS;
}

static void _free_acl(struct _mosquitto_acl *acl)
{
  if(!acl) return;

  if(acl->next){
    _free_acl(acl->next);
  }
  if(acl->topic){
    free(acl->topic);
  }
  free(acl);
}

static void _free_client_info(client_info *info)
{
  if(!info) return;

  if(info->common_name){
    free(info->common_name);
  }
  if(info->organization){
    free(info->organization);
  }
  if(info->organizational_unit){
    free(info->organizational_unit);
  }
  free(info);
}

int mosquitto_auth_plugin_version(void) {
  return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  int i;
  struct mosquitto_auth_opt *o;
  printf("FABUS: mosquitto_auth_plugin_init\n");
  struct auth_db *db;
  *user_data = (struct auth_db *)malloc(sizeof(struct auth_db));

  if (*user_data == NULL) {
    printf("error allocting user_data\n");
    return MOSQ_ERR_UNKNOWN;
  }
  memset(*user_data, 0, sizeof(struct auth_db));
  db = *user_data;
  db->acl_patterns = NULL;
  db->acl_file = NULL;

  for (i = 0, o = auth_opts; i < auth_opt_count; i++, o++) {
    if (!strcmp(o->key, "acl_file")) db->acl_file = strdup(o->value);
  }
  if (db->acl_file == NULL) {
    printf("acl_file option missing\n");
    return MOSQ_ERR_UNKNOWN;
  }

  return _aclfile_parse(db, db->acl_file);
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  //printf( "FABUS: mosquitto_auth_plugin_cleanup\n");
  struct auth_db *db = (struct auth_db *)user_data;

  if(db->acl_patterns){
    _free_acl(db->acl_patterns);
    db->acl_patterns = NULL;
  }
  free(db);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {


  //printf("FABUS: mosquitto_auth_security_init\n");
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload){

  //printf("FABUS: mosquitto_auth_security_cleanup\n");
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access) {
  printf("FABUS: mosquitto_auth_acl_check(clientid: %s, username: %s, topic: %s, access: %d)\n", clientid, username, topic, access);
  struct auth_db *db = (struct auth_db *)user_data;
  char *local_acl;
  struct _mosquitto_acl *acl_root;
  bool result;
  int i;
  int len, tlen, ilen, clen, ulen, olen;
  char *s;

  client_info *info = malloc(sizeof(client_info));

  if(!db || !topic) return MOSQ_ERR_INVAL;
  if(!db->acl_patterns) return MOSQ_ERR_SUCCESS;

  if (_parse_subject(username, info) != 0) {
    return MOSQ_ERR_ACL_DENIED;
  }
  printf("FABUS: CN=%s O=%s OU=%s\n", info->common_name, info->organization, info->organizational_unit);


  acl_root = db->acl_patterns;
  /* Loop through all pattern ACLs. */
  ilen = strlen(clientid);
  while(acl_root){
    tlen = strlen(acl_root->topic);

    if(acl_root->ucount && !info->common_name){
      acl_root = acl_root->next;
      continue;
    }

    len = tlen + acl_root->icount*(ilen-2);

    if(info->common_name){
      clen = strlen(info->common_name);
      len += acl_root->ccount*(clen-2);
    }else{
      clen = 0;
    }
    if(info->organizational_unit){
      ulen = strlen(info->organizational_unit);
      len += acl_root->ucount*(ulen-2);
    }else{
      ulen = 0;
    }
    if(info->organization){
      olen = strlen(info->organization);
      len += acl_root->ocount*(olen-2);
    }else{
      olen = 0;
    }
    
    local_acl = malloc(len+1);
    if(!local_acl) return 1; // FIXME
    s = local_acl;
    for(i=0; i<tlen; i++){
      if(i<tlen-1 && acl_root->topic[i] == '%'){
        if(acl_root->topic[i+1] == 'i'){
          i++;
          strncpy(s, clientid, ilen);
          s+=ilen;
          continue;
        }else if(info->common_name && acl_root->topic[i+1] == 'c'){
          i++;
          strncpy(s, info->common_name, clen);
          s+=clen;
          continue;
        }else if(info->organizational_unit && acl_root->topic[i+1] == 'u'){
          i++;
          strncpy(s, info->organizational_unit, ulen);
          s+=ulen;
          continue;
        }else if(info->organization && acl_root->topic[i+1] == 'o'){
          i++;
          strncpy(s, info->organization, olen);
          s+=olen;
          continue;
        }
      }
      s[0] = acl_root->topic[i];
      s++;
    }
    local_acl[len] = '\0';

    mosquitto_topic_matches_sub(local_acl, topic, &result);
    free(local_acl);
    if(result){
      if(access & acl_root->access){
        /* And access is allowed. */
        printf("acl allowed\n");
        _free_client_info(info);
        return MOSQ_ERR_SUCCESS;
      }
    }

    acl_root = acl_root->next;
  }
  printf("acl denied\n");
  _free_client_info(info);
  return MOSQ_ERR_ACL_DENIED;
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password) {
  //printf("FABUS: mosquitto_auth_unpwd_check(username: %s, password: %s)\n", username, password);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len) {
  return 1; 
}
