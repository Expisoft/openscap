/**
 * @file   user.c
 * @brief  user probe
 * @author "Stefan Gustafsson" <sg@expisoft.com>
 *
 * 2015/10/15 sg@expisoft.com
 *  This probe is able to process an user_object as defined in OVAL 5.?.
 *
 */

/*
 * Copyright 2015 Expisoft AB., Stockholm Sweden.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Stefan Gustafsson <sg@expisoft.com>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_STDIO_EXT_H
# include <stdio_ext.h>
#endif
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <time.h>
#include <pcre.h>

#include "seap.h"
#include "probe-api.h"
#include "probe/entcmp.h"
#include "alloc.h"
#include "common/debug_priv.h"

/* FIX: oval_types.h:327 need to be more specific to avoid collition with msxml */
#define XML_ERROR	WINDOWS_XML_ERROR

#include <windows.h>
#include <lm.h>

void split_user(const char* user,char** username,char** domain);
void collect_user(probe_ctx* ctx,USER_INFO_2* pInfo);

int probe_main(probe_ctx *ctx, void *arg)
{
	SEXP_t*					probe_in;
	SEXP_t*					ent;
	SEXP_t*					val;
	char*					user = NULL;
	int						user_op = OVAL_OPERATION_EQUALS;
	pcre*					re = NULL;
	const char*				estr = NULL;
	int						eoff = -1;
	ULONG					cbComputerName;
	char*					computer;
	char*					username;
	char*					domain;

	dI("Enter\n");

	probe_in = probe_ctx_getobject(ctx);
	if (probe_in == NULL) {
		return PROBE_ENOOBJ;
	}

	ent = probe_obj_getent(probe_in, "user", 1);
	if (ent == NULL) {
        dI("%s: not found\n", "user");
		return (PROBE_ENOENT);
	}

    val = probe_ent_getval(ent);
    if (val == NULL) {
        dI("%s: no value\n", "user");
        SEXP_free(ent);
        return (PROBE_ENOVAL);
    }

    user = SEXP_string_cstr(val);

	user_op = probe_ent_getoperation(ent,OVAL_OPERATION_EQUALS);

    SEXP_free(val);
	SEXP_free(ent);

	cbComputerName = 0;

	GetComputerNameExA(ComputerNamePhysicalDnsHostname,NULL,&cbComputerName);

	computer = calloc(cbComputerName,sizeof(CHAR));

	if (!GetComputerNameExA(ComputerNamePhysicalDnsHostname,computer,&cbComputerName)) {
		dE("GetComputerNameExA failed\n");
        return (PROBE_EINVAL);
	}

	/* Split argument user into username and domain */
	split_user(user,&username,&domain);

	dI("%s %d %s %s %s\n",user,user_op,username,domain,computer);

	/* If we got an domain that is not this computer, we need to send the request to a DC */
	if (domain && strcasecmp(domain,computer)!=0) {
		dE("Domain user lookups not supported yet\n");
	} 

	if (user_op == OVAL_OPERATION_PATTERN_MATCH) {

		re = pcre_compile(username, PCRE_UTF8, &estr, &eoff, NULL);
		if (re == NULL) {
			free(username);
			free(domain);
			free(computer);
			return (PROBE_EINVAL);
		}

	}

	NET_API_STATUS	rc;
    DWORD			nRecords = 0;
    DWORD			nTotal = 0;
    USER_INFO_2*	pInfo2 = NULL;
	DWORD			hResume = 0;
	unsigned int	i;

	for(;;) {
		
		rc = NetUserEnum(NULL,2,0,(LPBYTE*)&pInfo2,MAX_PREFERRED_LENGTH,&nRecords,&nTotal,&hResume);
		if ((rc != NERR_Success) && (rc != ERROR_MORE_DATA)) {
			dE("NetUserEnum failed %d\n",rc);
			break;
		}

		for (i=0; i<nRecords; i++) {
			char	szUser[257];

			sprintf(szUser,"%ls",pInfo2[i].usri2_name);

			switch(user_op) {
			case OVAL_OPERATION_EQUALS:
				if (strcmp(username,szUser) == 0) {
					
					collect_user(ctx,&pInfo2[i]);

				}
				break;
			case OVAL_OPERATION_PATTERN_MATCH:

				rc = pcre_exec(re, NULL,szUser,strlen(szUser), 0, 0, NULL, 0);
				if (rc == 0) {
					collect_user(ctx,&pInfo2[i]);
				}
				break;
			default:
				dE("unsupported operation");
				return (PROBE_EINVAL);
			}
		}

		NetApiBufferFree(pInfo2);

		if (rc == NERR_Success) {
			break;
		}
	}

	free(username);
	free(domain);
	free(computer);

	return 0;
}

void collect_user(probe_ctx* ctx,USER_INFO_2* pInfo) {
	SEXP_t*		ent;
	char		szUser[257];
	bool		enabled;

	dI("collect %ls\n",pInfo->usri2_name);

	sprintf(szUser,"%ls",pInfo->usri2_name);

	enabled = !(pInfo->usri2_flags & UF_ACCOUNTDISABLE);

	ent = probe_item_create(OVAL_WINDOWS_USER, NULL,
		"user",OVAL_DATATYPE_STRING,szUser,
		"enabled",OVAL_DATATYPE_BOOLEAN,enabled,
		"last_logon",OVAL_DATATYPE_BOOLEAN,(uint64_t)pInfo->usri2_last_logon,
		NULL);

	/*
	 * Lost all global groups this user belongs to
	 */
	NET_API_STATUS			rc;
    DWORD					nRecords = 0;
    DWORD					nTotal = 0;
    LPGROUP_USERS_INFO_0	pGlobalGroups = NULL;
	unsigned int			i;

	rc = NetUserGetGroups(NULL,pInfo->usri2_name,0,(LPBYTE*)&pGlobalGroups,MAX_PREFERRED_LENGTH,&nRecords,&nTotal);
	if (rc != NERR_Success) {
		dE("NetUserGetGroups failed %d\n",rc);
	} else {

		for (i=0; i<nRecords; i++) {
			char	szGroup[257];
			SEXP_t	ti;

			sprintf(szGroup,"%ls",pGlobalGroups[i].grui0_name);

			dI("group %s\n",szGroup);

			probe_item_ent_add(ent,"group", NULL,SEXP_string_new_r(&ti,szGroup,strlen(szGroup)));
		}

		NetApiBufferFree(pGlobalGroups);
	}

	/*
	 * List users local groups
	 */
	LPLOCALGROUP_USERS_INFO_0	pLocalGroups = NULL;

	rc = NetUserGetLocalGroups(NULL,pInfo->usri2_name,0,LG_INCLUDE_INDIRECT,(LPBYTE*)&pLocalGroups,MAX_PREFERRED_LENGTH,&nRecords,&nTotal);
	if (rc != NERR_Success) {
		dE("NetUserGetLocalGroups failed %d\n",rc);
	} else {
		for (i=0; i<nRecords; i++) {
			char	szGroup[257];
			SEXP_t	ti;

			sprintf(szGroup,"%ls",pLocalGroups[i].lgrui0_name);

			dI("group %s\n",szGroup);

			probe_item_ent_add(ent,"group", NULL,SEXP_string_new_r(&ti,szGroup,strlen(szGroup)));
		}

		NetApiBufferFree(pLocalGroups);
	}

	probe_item_collect(ctx, ent);
}

void split_user(const char* user,char** username,char** domain) {
	char*	p;

	p = strchr(user,'\\');
	if (p == NULL) {
		*username = strdup(user);
		*domain = NULL;
	} else {
		*domain = strndup(user,p-user);
		*username = strdup(p+1);
	}
}
