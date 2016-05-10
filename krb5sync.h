/*
 Copyright 2011 The Trustees of Columbia University in the City of New York
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 
 */

#include "config.h"
//#define CACHE_NAME "MEMORY:krb5_sync"

struct dnokay {
	char dn[4096];
	int parts;
	struct dnokay * next;
};

struct k5scfg {
	char * syslog;
	char * ldapuri;
	char * binddn;
	char * basedn;
	char * realmstring;
	char password[128];
	LDAP * ldConn;
        int ldapretries;
        struct timeval ldtimeout;

};

krb5_principal get_ad_principal(krb5_context kcx, struct k5scfg * cx, krb5_principal pin);
int check_update_okay(struct k5scfg * cx, char * principal, char ** dnout);
int get_ldap_conn(struct k5scfg * cx);
int get_next_dn(struct dnokay * out, FILE * in);

kadm5_ret_t handle_chpass(krb5_context context,
	kadm5_hook_modinfo *modinfo,
	int stage,
	krb5_principal princ, krb5_boolean keepold,
	int n_ks_tuple,
	krb5_key_salt_tuple *ks_tuple,
	const char *newpass);
