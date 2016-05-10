/*
 * Copyright (C)  2015  Olof <olof.faircreek@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldap.h>
#include <krb5/kadm5_hook_plugin.h>
#include <errno.h>
#include "krb5sync.h"


int get_ldap_conn(struct k5scfg * cx) {
	int rc, i = 0, option = LDAP_VERSION3;
        int reqcert = LDAP_OPT_X_TLS_DEMAND;

	if(cx->ldConn)
		ldap_unbind_s(cx->ldConn);
	rc = ldap_initialize(&cx->ldConn, cx->ldapuri);
	if(rc != 0) {
		com_err("kadmind", rc, "Error initializing LDAP: %s",
				ldap_err2string(rc));
		return rc;
	}

	rc = ldap_set_option(cx->ldConn, LDAP_OPT_PROTOCOL_VERSION, &option);
	if(rc != 0) {
		com_err("kadmind", rc, "Error setting protocol version: %s",
				ldap_err2string(rc));
		return rc;
	}
	ldap_set_option(cx->ldConn, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

	rc = ldap_set_option(cx->ldConn, LDAP_OPT_TIMEOUT, &cx->ldtimeout);
	if(rc != 0) {
		com_err("kadmind", rc, "Error setting timeout to %d seconds: %s",
				cx->ldtimeout.tv_sec, ldap_err2string(rc));
		return rc;
	}

	rc = ldap_set_option (cx->ldConn, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqcert);
	if(rc != 0) {
		com_err("kadmind", rc, "Error setting cert: %s",
				ldap_err2string(rc));
		return rc;
	}


	rc = ldap_start_tls_s(cx->ldConn, NULL, NULL);	

	if(rc != 0) {
		com_err("kadmind", rc, "Error starting TLS: %s",
				ldap_err2string(rc));
		return rc;
	}


	do {
		if(cx->binddn)
			rc = ldap_simple_bind_s(cx->ldConn, cx->binddn, cx->password);
	} while(++i < cx->ldapretries && rc != 0);
	
	if(rc != 0) {
		com_err("kadmind", rc, "Error connecting to LDAP server: %s",
			ldap_err2string(rc));
		return rc;
	} else {
		com_err("kadmind", rc, "Connected %s", ldap_err2string(rc));
	}

	return 0;
}



kadm5_ret_t handle_chpass(krb5_context kcx,
       kadm5_hook_modinfo *modinfo,
       int stage,
       krb5_principal princ, krb5_boolean keepold,
       int n_ks_tuple,
       krb5_key_salt_tuple *ks_tuple,
       const char *newpass)
{

        char * tmp, *filter, *filter2,*filter3,*filter4, * dn, * name;
	int size;
        int parts = 1, i = 0, rc, cp;
        LDAPMessage * msg = NULL;
        char * noattrs[2] = { "1.1", NULL };
        FILE * adobjects = NULL;
        struct dnokay * curdn;
  	LDAPMod mod, mod2;
    	LDAPMod *mods[3];
	char *strvalsnew[2];

    	mod.mod_op = LDAP_MOD_REPLACE;
	mod.mod_type = (char *) "userPassword";
	mod.mod_values = strvalsnew;

    	mods[0] = &mod;
    	mods[1] = NULL;

	strvalsnew[0] = (char *) newpass;
	strvalsnew[1] = NULL;



	if(stage == KADM5_HOOK_STAGE_POSTCOMMIT)
		return 0;
	if(newpass == NULL) // Don't sync null passwords 
		return 0;

	
	struct k5scfg * cx = (struct k5scfg*)modinfo;
        char * targetUnparsed = NULL;
        int result_code;
        krb5_data result_code_string, result_string;

	krb5_unparse_name(kcx, princ, &name);	

	size = strlen(cx->realmstring);
	size = strlen(name) - size; 
	com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS,"Size is: %d", size);

	filter = malloc(sizeof("(uid=)") + strlen(name) + 1);
	filter2 = malloc(sizeof("uid=,") + size + 1);
	strcpy(filter2,"uid=");
	com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS,"x%sx",filter2);
	filter3 = filter2; 
	com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS,"%p",filter3);
	filter3 = filter2 + 4;
	com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS,"%p",filter3);
	strncat(filter3,name, size);
	com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS,"x%sx",filter2);
	filter3 = filter3 + size;
	com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS,"%p",filter3);
	strcpy(filter3,",");
	com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS,"x%sx",filter2);

	sprintf(filter, "(uid=%s)", name);
	filter4= malloc(strlen(filter2) + strlen(cx->basedn) + 1);
	sprintf(filter4,"%s%s",filter2,cx->basedn);

	rc = ldap_modify_s(cx->ldConn,filter4,mods);
	com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS, "mod %s\n",ldap_err2string(rc));

	

	com_err("kadmind", KADM5_MISSING_KRB5_CONF_PARAMS,"Pric is: %s, %s, %s, x%sx, y%sy", filter, newpass, cx->realmstring, filter2, filter4);
	

        rc = ldap_search_ext_s(cx->ldConn, cx->basedn, LDAP_SCOPE_SUBTREE, filter2,
                noattrs, 0, NULL, NULL, NULL, 0, &msg);

	if (rc != 0) {
		com_err("kadmind", result_code, "Syncing password for %s on Active Directory: %s; %s",
				targetUnparsed, result_code_string.data, result_string.data);
	}

 	krb5_free_unparsed_name(kcx,name);	
	return rc;
}
