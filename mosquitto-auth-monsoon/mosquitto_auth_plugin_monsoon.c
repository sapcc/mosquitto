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

struct _mosquitto_acl_user{
  struct _mosquitto_acl_user *next;
  char *username;
  client_info *user_info;
  struct _mosquitto_acl *acl;
};

typedef struct {
  struct _mosquitto_acl_user *acl_list;
  struct _mosquitto_acl *acl_patterns;
  char * acl_file;
} auth_db;

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

static client_info *_malloc_client_info() {
  client_info *i = malloc(sizeof(client_info));
  if (!i) return NULL;
  memset(i, 0, sizeof(client_info)); 
  i->common_name = NULL;
  i->organization = NULL;
  i->organizational_unit = NULL;
  return i;
}

static auth_db *_malloc_auth_db() {
  auth_db *d = malloc(sizeof(auth_db));
  if (!d) return NULL;
  memset(d, 0, sizeof(auth_db));
  d->acl_patterns = NULL;
  d->acl_list = NULL;
  d->acl_file = NULL;
  return d;
}

int _parse_subject(const char *subject, client_info *info) {
  if (!subject) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "No subject given");
    return -1;
  }
  LDAPDN dn = NULL;
  int err = ldap_str2dn(subject, &dn , LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PEDANTIC);
  if (err != 0) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to parse certificate subject \"%s\": %s", subject, ldap_err2string(err));
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

int _add_acl(auth_db *db, const char *user, const char *topic, int access)
{
  mosquitto_log_printf(MOSQ_LOG_DEBUG, "Add acl for %s; topic: %s", user, topic);
  struct _mosquitto_acl_user *acl_user=NULL, *user_tail;
  struct _mosquitto_acl *acl, *acl_tail;
  char *local_topic;
  bool new_user = false;

  if(!db || !topic) return MOSQ_ERR_INVAL;

  local_topic = strdup(topic);
  if(!local_topic){
    return MOSQ_ERR_NOMEM;
  }

  if(db->acl_list){
    user_tail = db->acl_list;
    while(user_tail){
      if(user == NULL){
        if(user_tail->username == NULL){
          acl_user = user_tail;
          break;
        }
      }else if(user_tail->username && !strcmp(user_tail->username, user)){
        acl_user = user_tail;
        break;
      }
      user_tail = user_tail->next;
    }
  }
  if(!acl_user){
    acl_user = malloc(sizeof(struct _mosquitto_acl_user));
    if(!acl_user){
      free(local_topic);
      return MOSQ_ERR_NOMEM;
    }
    new_user = true;
    if(user){
      acl_user->username = strdup(user);
      if(!acl_user->username){
        free(local_topic);
        free(acl_user);
        return MOSQ_ERR_NOMEM;
      }
      acl_user->user_info = _malloc_client_info();
      if (!acl_user->user_info) {
        free(local_topic);
        free(acl_user->username);
        free(acl_user);
        return MOSQ_ERR_NOMEM;
      }
      if (_parse_subject(user, acl_user->user_info) != 0) {
        free(local_topic);
        _free_client_info(acl_user->user_info);
        free(acl_user->username);
        free(acl_user);
        return MOSQ_ERR_INVAL;
      }

    }else{
      acl_user->username = NULL;
    }
    acl_user->next = NULL;
    acl_user->acl = NULL;
  }

  acl = malloc(sizeof(struct _mosquitto_acl));
  if(!acl){
    free(local_topic);
    return MOSQ_ERR_NOMEM;
  }
  acl->access = access;
  acl->topic = local_topic;
  acl->next = NULL;
  acl->ccount = 0;
  acl->ucount = 0;

  /* Add acl to user acl list */
  if(acl_user->acl){
    acl_tail = acl_user->acl;
    while(acl_tail->next){
      acl_tail = acl_tail->next;
    }
    acl_tail->next = acl;
  }else{
    acl_user->acl = acl;
  }

  if(new_user){
    /* Add to end of list */
    if(db->acl_list){
      user_tail = db->acl_list;
      while(user_tail->next){
        user_tail = user_tail->next;
      }
      user_tail->next = acl_user;
    }else{
      db->acl_list = acl_user;
    }
  }

  return MOSQ_ERR_SUCCESS;
}


int _add_acl_pattern(auth_db *db, const char *topic, int access)
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


static int _aclfile_parse(auth_db *db, const char *filepath)
{
  FILE *aclfile;
  char buf[1024];
  char *token;
  char *user = NULL;
  char *topic;
  char *access_s;
  int access;
  int rc;
  int slen;
  int topic_pattern;
  char *saveptr = NULL;

  aclfile = fopen(filepath, "rt");
  if(!aclfile){
    mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Unable to open acl_file \"%s\".", filepath);
    return 1;
  }

  // topic [read|write] <topic> 
  // user <user>

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
      if(!strcmp(token, "topic") || !strcmp(token, "pattern")){
        if(!strcmp(token, "topic")){
          topic_pattern = 0;
        }else{
          topic_pattern = 1;
        }

        access_s = strtok_r(NULL, " ", &saveptr);
        if(!access_s){
          mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Empty topic in acl_file.");
          if(user) free(user);
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
            mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Invalid topic access type \"%s\" in acl_file.", access_s);
            if(user) free(user);
            fclose(aclfile);
            return MOSQ_ERR_INVAL;
          }
        }else{
          access = MOSQ_ACL_READ | MOSQ_ACL_WRITE;
        }
        if(topic_pattern == 0){
          rc = _add_acl(db, user, topic, access);
        }else{
          rc = _add_acl_pattern(db, topic, access);
        }
        if(rc){
          if(user) free(user);
          fclose(aclfile);
          return rc;
        }
      }else if(!strcmp(token, "user")){
        token = strtok_r(NULL, "", &saveptr);
        if(token){
          /* Ignore duplicate spaces */
          while(token[0] == ' '){
            token++;
          }
          if(user) free(user);
          user = strdup(token);
          if(!user){
            fclose(aclfile);
            return MOSQ_ERR_NOMEM;
          }
        }else{
          //mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Missing username in acl_file.");
          printf("Error: Missing username in acl_file.\n");
          if(user) free(user);
          fclose(aclfile);
          return 1;
        }
      }
    }
  }

  if(user) free(user);
  fclose(aclfile);

  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_version(void) {
  return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  int i;
  struct mosquitto_auth_opt *o;
  mosquitto_log_printf(MOSQ_LOG_INFO, "mosquitto_auth_plugin_init");
  auth_db *db;
  *user_data = _malloc_auth_db();

  if (*user_data == NULL) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "error allocting user_data");
    return MOSQ_ERR_UNKNOWN;
  }
  db = *user_data;
  db->acl_patterns = NULL;
  db->acl_list = NULL;
  db->acl_file = NULL;

  for (i = 0, o = auth_opts; i < auth_opt_count; i++, o++) {
    if (!strcmp(o->key, "acl_file")) db->acl_file = strdup(o->value);
  }
  if (db->acl_file == NULL) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "acl_file option missing");
    return MOSQ_ERR_UNKNOWN;
  }

  return _aclfile_parse(db, db->acl_file);
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  auth_db *db = (auth_db *)user_data;
  struct _mosquitto_acl_user *user_tail;

  while(db->acl_list){
    user_tail = db->acl_list->next;

    _free_acl(db->acl_list->acl);
    if(db->acl_list->username){
      free(db->acl_list->username);
    }
    _free_client_info(db->acl_list->user_info);
    free(db->acl_list);
    
    db->acl_list = user_tail;
  }

  if(db->acl_patterns){
    _free_acl(db->acl_patterns);
    db->acl_patterns = NULL;
  }
  free(db);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access) {
  mosquitto_log_printf(MOSQ_LOG_DEBUG, "mosquitto_auth_acl_check(clientid: %s, username: %s, topic: %s, access: %d)", clientid, username, topic, access);
  auth_db *db = (auth_db *)user_data;
  char *local_acl;
  struct _mosquitto_acl *acl_root;
  struct _mosquitto_acl_user *acl_user_root;
  bool result;
  int i;
  int len, tlen, ilen, clen, ulen, olen;
  char *s;

  if(!db || !topic) return MOSQ_ERR_INVAL;
  if(!db->acl_list && !db->acl_patterns) return MOSQ_ERR_SUCCESS;

  client_info *info = _malloc_client_info();
  if (!info) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to allocate memory for client_info");
    return MOSQ_ERR_ACL_DENIED;
  }

  if (_parse_subject(username, info) != 0) {
    _free_client_info(info);
    return MOSQ_ERR_ACL_DENIED;
  }
  mosquitto_log_printf(MOSQ_LOG_DEBUG, "Extracted from username: CN=%s O=%s OU=%s", info->common_name, info->organization, info->organizational_unit);

  acl_user_root = db->acl_list;
  while(acl_user_root) {

    mosquitto_log_printf(MOSQ_LOG_DEBUG, "Checking acl for %s", acl_user_root->username);
    //skip if no user_info available
    if (!acl_user_root->user_info) {
      mosquitto_log_printf(MOSQ_LOG_DEBUG, "No user_info. Skipping");
      acl_user_root = acl_user_root->next;
      continue;
    }
    if (acl_user_root->user_info->common_name && (!info->common_name || strcmp(acl_user_root->user_info->common_name, info->common_name  ))) {
      mosquitto_log_printf(MOSQ_LOG_DEBUG, "common_name does not match: %s", acl_user_root->user_info->common_name );
      acl_user_root = acl_user_root->next;
      continue;
    }
    if (acl_user_root->user_info->organizational_unit && (!info->organizational_unit || strcmp(acl_user_root->user_info->organizational_unit, info->organizational_unit ))) {
      mosquitto_log_printf(MOSQ_LOG_DEBUG, "unit does not match: %s", acl_user_root->user_info->organizational_unit );
      acl_user_root = acl_user_root->next;
      continue;
    }
    if (acl_user_root->user_info->organization && (!info->organization || strcmp(acl_user_root->user_info->organization, info->organization ))) {
      mosquitto_log_printf(MOSQ_LOG_DEBUG, "organization does not match: %s", acl_user_root->user_info->organization );
      acl_user_root = acl_user_root->next;
      continue;
    }

    acl_root = acl_user_root->acl;
    /* Loop through all ACLs for the user. */
    while(acl_root){
      /* Loop through the topic looking for matches to this ACL. */

      /* If subscription starts with $, acl_root->topic must also start with $. */
      if(topic[0] == '$' && acl_root->topic[0] != '$'){
        acl_root = acl_root->next;
        continue;
      }
      mosquitto_topic_matches_sub(acl_root->topic, topic, &result);
      if(result){
        if(access & acl_root->access){
          mosquitto_log_printf(MOSQ_LOG_DEBUG, "Topic %s matches %s. Access granted", topic, acl_root->topic);
          _free_client_info(info);
          /* And access is allowed. */
          return MOSQ_ERR_SUCCESS;
        }
      }
      acl_root = acl_root->next;
    }
    acl_user_root = acl_user_root->next;
  }

  acl_root = db->acl_patterns;
  /* Loop through all pattern ACLs. */
  ilen = strlen(clientid);
  while(acl_root){
    tlen = strlen(acl_root->topic);
    //mosquitto_log_printf(MOSQ_LOG_DEBUG, "processing pattern %s", acl_root->topic);

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
    if(!local_acl) {
      mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to allocate memory for local_acl");
      _free_client_info(info);
      return MOSQ_ERR_ACL_DENIED;
    }
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
        mosquitto_log_printf(MOSQ_LOG_DEBUG, "Topic %s matched by %s. Access granted.", topic, acl_root->topic);
        _free_client_info(info);
        return MOSQ_ERR_SUCCESS;
      }
    }

    acl_root = acl_root->next;
  }
  mosquitto_log_printf(MOSQ_LOG_DEBUG, "Access denied");
  _free_client_info(info);
  return MOSQ_ERR_ACL_DENIED;
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len) {
  return 1; 
}
