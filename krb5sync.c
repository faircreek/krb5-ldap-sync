/*
 Copyright (C) Olof <olof.faircreek@gmail.com>
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

#include <krb5/kadm5_hook_plugin.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <ldap.h>
#include "krb5sync.h"

void cleanup(krb5_context kcx, kadm5_hook_modinfo * modinfo);

void config_string(krb5_context kcx, const char *opt, char **result)
{
    const char *defval = "";
	
    krb5_appdefault_string(kcx, "sync", NULL, opt, defval, result);
    if (*result != NULL && (*result)[0] == '\0') {
        free(*result);
        *result = NULL;
    }
}

void cleanup(krb5_context kcx, kadm5_hook_modinfo * modinfo) {
	struct k5scfg * cx = (struct k5scfg*)modinfo;
	if(cx->basedn)
		free(cx->basedn);
	if(cx->ldapuri)
		free(cx->ldapuri);
	if(cx->binddn)
		free(cx->binddn);
	if(cx->realmstring)
		free(cx->realmstring);
	if(cx->syslog) 
		free(cx->syslog);
	if(*cx->password) {
		memset(cx->password, 0, 128);
	}
	if(cx->ldConn)
		ldap_unbind_s(cx->ldConn);
	if(cx)
		free(cx);
}


kadm5_ret_t handle_init(krb5_context kcx, kadm5_hook_modinfo ** modinfo) {
	struct k5scfg * cx = malloc(sizeof(struct k5scfg));
	char * path = NULL,  *buffer;
	FILE * file = NULL;
	int rc, i, dncount = 0;
	
	if(cx == NULL)
		return KADM5_FAILURE;
	
	memset(cx, 0, sizeof(struct k5scfg));

	*modinfo = (kadm5_hook_modinfo *)cx;
	config_string(kcx, "basedn", &cx->basedn);
	config_string(kcx, "ldapuri", &cx->ldapuri);
	config_string(kcx, "password", &path);
	config_string(kcx, "binddn", &cx->binddn);
	config_string(kcx, "realmstring", &cx->realmstring);
	config_string(kcx, "syslog", &cx->syslog);

	if(!cx->basedn || !cx->ldapuri || !cx->binddn) {
		com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS, "Must specify both basedn and ldapuri. %s, %s, %s", cx->basedn, cx->ldapuri, cx->binddn);
		cleanup(kcx, *modinfo);
		return KADM5_MISSING_KRB5_CONF_PARAMS;
	} else {
		com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS, "Must specify both basedn and ldapuri. %s, %s, %s", cx->basedn, cx->ldapuri, cx->binddn);
	}
	
	
	if(path) {
		file = fopen(path, "r");
		free(path);
		path = NULL;
		*cx->password = 0;
		fgets(cx->password, 128, file);
		fclose(file);
		rc = strlen(cx->password) - 1;
		if(cx->password[rc] == '\n') {
			cx->password[rc] = 0;
			rc--;
		}
		if(rc == 0) {
			cleanup(kcx, *modinfo);
			com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS, "Must specify a password to connect to AD");
			return KADM5_MISSING_KRB5_CONF_PARAMS;
		}
	} else {

		com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS, "Must specify a password to connect to AD");
		return KADM5_MISSING_KRB5_CONF_PARAMS;
	}



	config_string(kcx, "ldapconnectretries", &buffer);

	if(buffer) {
		cx->ldapretries = atoi(buffer);
		free(buffer);
	} else {
		cx->ldapretries = 3;
	}

	config_string(kcx, "ldaptimeout", &buffer);

	if(buffer) {
		cx->ldtimeout.tv_sec = atoi(buffer);
		free(buffer);
	} else {
		cx->ldtimeout.tv_sec = -1;
	}

	rc = get_ldap_conn(cx);
	if(rc != 0) {
		com_err("kadmind", rc, "Failed to initialize LDAP connection to LDAP server. Cannot continue.");
		cleanup(kcx, *modinfo);
		return KADM5_NO_SRV;
	} else {
		com_err("kadmind", rc, "Connected");
	}

	return 0;
}

krb5_error_code kadm5_hook_sync_initvt(krb5_context kcx, int maj_ver, int min_ver,
                       krb5_plugin_vtable vtable)
{
    kadm5_hook_vftable_1 *vt = (kadm5_hook_vftable_1 *) vtable;
    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
	
    vt->name = "sync";
    vt->chpass = handle_chpass;
	vt->init = handle_init;
	vt->fini = cleanup;
    return 0;
}
