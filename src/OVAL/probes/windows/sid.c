/**
 * @file   sid.c
 * @brief  sid probe
 * @author "Stefan Gustafsson" <sg@expisoft.com>
 *
 * 2015/10/15 sg@expisoft.com
 *  This probe is able to process an sid_object as defined in OVAL 5.?.
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
#include <wchar.h>
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
#include <sddl.h>
#include <ntsecapi.h>

SEXP_t* trustees_from_sid(SEXP_t* list,const char* name);
SEXP_t*	list_trustees(void);
int		expand_trustee(SEXP_t* list,const char* trustee,bool include_group,bool resolve_group);
int		collect_trustee(probe_ctx* ctx,const char* trustee);

LPWSTR	g_pwszComputerName = NULL;

int probe_main(probe_ctx *ctx, void *arg)
{
	SEXP_t*		probe_in;
	SEXP_t*		trustee_ent;
	SEXP_t*		val;
	SEXP_t*		behaviors;
	char*		trustee  = NULL;
	int			trustee_op = OVAL_OPERATION_EQUALS;
	bool		include_group = true;
	bool		resolve_group = false;
	int			rc;
	SEXP_t*		trustee_list;
	int			len,i;
	DWORD		cbComputerName;

	probe_in = probe_ctx_getobject(ctx);
	if (probe_in == NULL) {
		return PROBE_ENOOBJ;
	}

	trustee_ent = probe_obj_getent(probe_in, "trustee_name", 1);
	if (trustee_ent == NULL) {
		return (PROBE_ENOENT);
	}

    val = probe_ent_getval(trustee_ent);
    if (val == NULL) {
        dI("%s: no value\n", "trustee_name");
        SEXP_free(trustee_ent);
        return (PROBE_ENOVAL);
    }

    trustee = SEXP_string_cstr(val);
    SEXP_free(val);

	trustee_op = probe_ent_getoperation(trustee_ent,OVAL_OPERATION_EQUALS);

	SEXP_free(trustee_ent);

	if (trustee_op != OVAL_OPERATION_EQUALS && trustee_op != OVAL_OPERATION_PATTERN_MATCH) {
		dE("Invalid value of the `operation' attribute.\n");
        return (PROBE_EINVAL);
	}

	behaviors = probe_obj_getent(probe_in, "behaviors", 1);
	if (behaviors) {

		val = probe_ent_getattrval(behaviors, "include_group");
		if (val) {
			include_group = SEXP_number_getb(val);
		}

		val = probe_ent_getattrval(behaviors, "resolve_group");
		if (val) {
			resolve_group = SEXP_number_getb(val);
		}

	}

	dI("%s %s %s\n",trustee,include_group?"true":"false",resolve_group?"true":"false");

	cbComputerName = 0;

	GetComputerNameExW(ComputerNamePhysicalDnsHostname,NULL,&cbComputerName);

	g_pwszComputerName = calloc(cbComputerName,sizeof(WCHAR));

	if (!GetComputerNameExW(ComputerNamePhysicalDnsHostname,g_pwszComputerName,&cbComputerName)) {
		dE("GetComputerNameEx failed\n");
        return (PROBE_EINVAL);
	}

	// Create the list of all trustee we are collecting
	trustee_list = SEXP_list_new(NULL);

	if (trustee_op == OVAL_OPERATION_EQUALS) {
		rc = expand_trustee(trustee_list,trustee,include_group,resolve_group);		
		if (rc) {
			oscap_free(trustee);
			return rc;
		}

	} else {
		pcre*		re = NULL;
		const char*	estr = NULL;
		int			eoff = -1;

		re = pcre_compile(trustee, PCRE_UTF8, &estr, &eoff, NULL);
		if (re == NULL) {
			return (PROBE_EINVAL);
		}

		/* List all the trustees */
		val = list_trustees();
		if (val == NULL) {
			return (PROBE_EINVAL);
		}

		len = SEXP_list_length(val);
		if (len == -1) {
			return (PROBE_EINVAL);
		}

		for(i=0;i<len;i++) {
			char*	trustee_item;
			SEXP_t*	item;

			item = SEXP_list_nth(val,i+1);
			if (item == NULL) {
				continue;
			}

			trustee_item = SEXP_string_cstr(item);
			SEXP_free(item);

			rc = pcre_exec(re, NULL,trustee_item,strlen(trustee_item), 0, 0, NULL, 0);
			if (rc == 0) {
				// Expand this trustee, ignoring error
				expand_trustee(trustee_list,trustee_item,include_group,resolve_group);
			}

			oscap_free(trustee_item);
		}
	}

	/* Now collect the resulting list of trustees */
	len = SEXP_list_length(trustee_list);
	if (len == -1) {
		return (PROBE_EINVAL);
	}

	for(i=0;i<len;i++) {
		char*	trustee_item;
		SEXP_t*	item;

		item = SEXP_list_nth(trustee_list,i+1);
		if (item == NULL) {
			continue;
		}

		trustee_item = SEXP_string_cstr(item);
		SEXP_free(item);

		collect_trustee(ctx,trustee_item);

		oscap_free(trustee_item);
	}

	oscap_free(trustee);

	return 0;
}

SEXP_t* trustees_from_sid(SEXP_t* list,const char* name) {
	PSID			pSid = NULL;
	SID_NAME_USE	type;
	LPSTR			pAccountName = NULL;
	DWORD			cbAccountName = 0;
	LPSTR			pDomainName = NULL;
	DWORD			cbDomainName = 0;
	
	if(!ConvertStringSidToSid(name, &pSid)) {
		return NULL;
	} 

	LookupAccountSidA(NULL,pSid,NULL,&cbAccountName,NULL,&cbDomainName,&type);

	cbAccountName++;
	pAccountName = calloc(1,cbAccountName);

	cbDomainName++;
	pDomainName = calloc(1,cbDomainName);

	if (!LookupAccountSidA(NULL,pSid,pAccountName,&cbAccountName,pDomainName,&cbDomainName,&type)) {
		dE("LookupAccountSidA failed %d %s\n",GetLastError(),name);
		return NULL;
	}

	if(strcasecmp(pDomainName,"") != 0 && strcasecmp(pDomainName,"NT AUTHORITY") != 0 && strcasecmp(pDomainName,"BUILTIN") != 0) {
		SEXP_t	tmp;

		SEXP_list_add(list,SEXP_string_newf_r(&tmp,"%s\\%s",pDomainName,pAccountName));
	} else {
		SEXP_t	tmp;

		SEXP_list_add(list,SEXP_string_new_r(&tmp,pAccountName,cbAccountName));
	}

	LocalFree(pSid);
	free(pDomainName);
	free(pAccountName);

	return list;
}

SEXP_t*	list_trustees() {
	SEXP_t*	list;

	list = SEXP_list_new(NULL);

	/*
	 * Add all well-known-trustees
	 */
	trustees_from_sid(list,"S-1-1-0");			// Everyone
	trustees_from_sid(list,"S-1-3-0");			// Creator Owner
	trustees_from_sid(list,"S-1-3-1");			// Creator Group
	trustees_from_sid(list,"S-1-3-2");			// Creator Owner Server
	trustees_from_sid(list,"S-1-3-3");			// Creator Group Server
	trustees_from_sid(list,"S-1-5-1");			// Dialup
	trustees_from_sid(list,"S-1-5-2");			// Network
	trustees_from_sid(list,"S-1-5-3");			// Batch
	trustees_from_sid(list,"S-1-5-4");			// Interactive
	trustees_from_sid(list,"S-1-5-6");			// Service
	trustees_from_sid(list,"S-1-5-7");			// Anonymous
	trustees_from_sid(list,"S-1-5-8");			// Proxy
	trustees_from_sid(list,"S-1-5-9");			// Enterprise Domain Controllers
	trustees_from_sid(list,"S-1-5-11");			// Authenticated Users
	trustees_from_sid(list,"S-1-5-13");			// Terminal Server Users
	trustees_from_sid(list,"S-1-5-18");			// Local System
	trustees_from_sid(list,"S-1-5-19");			// NT Authority - local service
	trustees_from_sid(list,"S-1-5-20");			// NT Authority - network service
	trustees_from_sid(list,"S-1-5-32-544");		// Administrators
	trustees_from_sid(list,"S-1-5-32-545");		// Users
	trustees_from_sid(list,"S-1-5-32-546");		// Guests
	trustees_from_sid(list,"S-1-5-32-547");		// Power Users
	trustees_from_sid(list,"S-1-5-32-551");		// Backup Operators
	trustees_from_sid(list,"S-1-5-32-552");		// Replicators

	/*
	 * Add all local users
	 */ 
	NET_API_STATUS	rc;
    DWORD			nRecords = 0;
    DWORD			nTotal = 0;
    USER_INFO_0*	pInfo0 = NULL;
	DWORD			hResume = 0;
	unsigned int	i;

	for(;;) {
		
		rc = NetUserEnum(NULL,0,0,(LPBYTE*)&pInfo0,MAX_PREFERRED_LENGTH,&nRecords,&nTotal,&hResume);
		if ((rc != NERR_Success) && (rc != ERROR_MORE_DATA)) {
			break;
		}

		for (i=0; i<nRecords; i++) {
			SEXP_t	tmp;

//			SEXP_list_add(list,SEXP_string_newf_r(&tmp,"%ls\\%ls",g_pwszComputerName,pInfo0[i].usri0_name));
			SEXP_list_add(list,SEXP_string_newf_r(&tmp,"%ls",pInfo0[i].usri0_name));
		}

		NetApiBufferFree(pInfo0);

		if (rc == NERR_Success) {
			break;
		}
	}

	/*
	 * List all local groups
	 */
	LOCALGROUP_INFO_0* pGroupInfo0	= NULL;
	hResume							= 0;

	for(;;) { 
		rc = NetLocalGroupEnum(NULL,0,(LPBYTE*)&pGroupInfo0,MAX_PREFERRED_LENGTH,&nRecords,&nTotal,&hResume);
		if ((rc != NERR_Success) && (rc != ERROR_MORE_DATA)) {
			break;
		}

		for (i=0; i<nRecords; i++) {
			SEXP_t	tmp;

			SEXP_list_add(list,SEXP_string_newf_r(&tmp,"%ls\\%ls",g_pwszComputerName,pGroupInfo0[i].lgrpi0_name));
		}

		NetApiBufferFree(pGroupInfo0);

		if (rc == NERR_Success) {
			break;
		}
	}

	/*
	 * List all global groups
	 */

	GROUP_INFO_0*		pGroupInfo	= NULL;
	hResume							= 0;

	for(;;) {
		
		rc = NetGroupEnum(NULL,0,(LPBYTE*)&pGroupInfo,MAX_PREFERRED_LENGTH,&nRecords,&nTotal,&hResume);
		if ((rc != NERR_Success) && (rc != ERROR_MORE_DATA)) {
			break;
		}

		// Remove the stupid None group
		if (nRecords==1 && wcscmp(pGroupInfo[0].grpi0_name,L"None")==0) {
			break;
		}

		for (i=0; i<nRecords; i++) {
			SEXP_t	tmp;

			SEXP_list_add(list,SEXP_string_newf_r(&tmp,"%ls",pGroupInfo[i].grpi0_name));
		}

		NetApiBufferFree(pGroupInfo);

		if (rc == NERR_Success) {
			break;
		}
	}

	return list;
}

int expand_trustee(SEXP_t* list,const char* trustee,bool include_group,bool resolve_group) {
	PSID					pSid;
	DWORD					cbSid = 0;
	LPSTR					pDomainName;
	DWORD					cbDomainName = 0;
	SID_NAME_USE			type;
	NTSTATUS				rc;
	bool					bGroup = false;
	SEXP_t					tmp;

	LookupAccountName(NULL,trustee,NULL,&cbSid,NULL,&cbDomainName,&type);

	pSid = calloc(1,cbSid);

	cbDomainName++;
	pDomainName = calloc(1,cbDomainName);

	if (!LookupAccountName(NULL,trustee,pSid,&cbSid,pDomainName,&cbDomainName,&type)) {
		dE("LookupAccountName %s failed %d\n",trustee,GetLastError());
		return (PROBE_EINVAL);
	}

	switch(type) {
	case SidTypeUser:
		break;
	case SidTypeDomain:
		break;
	case SidTypeGroup:
	case SidTypeWellKnownGroup:
		bGroup = true;
		break;
	case SidTypeAlias:
		bGroup = true; 
		break;
	default:
		break;
	}

	if (bGroup && resolve_group) {
		DWORD						nRecords = 0;
		DWORD						nTotal = 0;
		LOCALGROUP_MEMBERS_INFO_2*	pMemberInfo2 = NULL;
		DWORD						hResume = 0;
		WCHAR						wzTrustee[514];
		ULONG						i;

		swprintf(wzTrustee,514,L"%s",trustee);

		for(;;) {
			
			rc = NetLocalGroupGetMembers(NULL,wzTrustee,2,(LPBYTE*)&pMemberInfo2,MAX_PREFERRED_LENGTH,&nRecords,&nTotal,&hResume);
			if ((rc != NERR_Success) && (rc != ERROR_MORE_DATA)) {
				break;
			}

			for (i=0; i<nRecords; i++) {
				char*	member_trustee;

				SEXP_string_newf_r(&tmp,"%ls",pMemberInfo2[i].lgrmi2_domainandname);

				member_trustee = SEXP_string_cstr(&tmp);

				expand_trustee(list,member_trustee,include_group,resolve_group);

				oscap_free(member_trustee);
			}

			NetApiBufferFree(pMemberInfo2);

			if (rc == NERR_Success) {
				break;
			}
		}
	}

	if (bGroup && !include_group) {
		return 0;
	}

	SEXP_list_add(list,SEXP_string_newf_r(&tmp,"%s",trustee));

	return 0;
}

int collect_trustee(probe_ctx* ctx,const char* trustee) {
	PSID					pSid;
	DWORD					cbSid = 0;
	LPSTR					pDomainName;
	DWORD					cbDomainName = 0;
	SID_NAME_USE			type;
	SEXP_t*					item;
	LPSTR					pszSid;

	dI("collect_trustee %s\n",trustee);

	LookupAccountName(NULL,trustee,NULL,&cbSid,NULL,&cbDomainName,&type);

	pSid = calloc(1,cbSid);

	cbDomainName++;
	pDomainName = calloc(1,cbDomainName);

	if (!LookupAccountName(NULL,trustee,pSid,&cbSid,pDomainName,&cbDomainName,&type)) {
		dE("LookupAccountName %s failed %d\n",trustee,GetLastError());
		return (PROBE_EINVAL);
	}

	ConvertSidToStringSid(pSid,&pszSid);

	item = probe_item_create(OVAL_WINDOWS_SID, NULL,
		"trustee_name",OVAL_DATATYPE_STRING,trustee,
		"trustee_sid",OVAL_DATATYPE_STRING,pszSid,
		"trustee_domain",OVAL_DATATYPE_STRING,pDomainName,
		NULL);

	probe_item_collect(ctx, item);

	LocalFree(pszSid);
	
	return (0);
}
