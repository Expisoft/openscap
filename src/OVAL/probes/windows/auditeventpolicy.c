/**
 * @file   auditeventpolicy.c
 * @brief  auditeventpolicy probe
 * @author "Stefan Gustafsson" <sg@expisoft.com>
 *
 * 2015/10/15 sg@expisoft.com
 *  This probe is able to process an auditeventpolicy as defined in OVAL 5.?.
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

#include "seap.h"
#include "probe-api.h"
#include "probe/entcmp.h"
#include "alloc.h"
#include "common/debug_priv.h"

/* FIX: oval_types.h:327 need to be more specific to avoid collition with msxml */
#define XML_ERROR	WINDOWS_XML_ERROR

#include <windows.h>
#include <ntsecapi.h>

const char* expand_audit_options(ULONG options);

int probe_main(probe_ctx *ctx, void *arg)
{
	SEXP_t*						ent;
	LSA_OBJECT_ATTRIBUTES		oa;
	NTSTATUS					rc;
	LSA_HANDLE					hPolicy;
	PPOLICY_AUDIT_EVENTS_INFO	pAuditInfo = NULL;

	ZeroMemory(&oa, sizeof(oa));

	rc = LsaOpenPolicy(NULL,&oa,POLICY_VIEW_AUDIT_INFORMATION,&hPolicy);
	if (rc != ERROR_SUCCESS) {
		return (PROBE_ENOVAL);
	}


	rc = LsaQueryInformationPolicy(hPolicy,PolicyAuditEventsInformation,(PVOID *)&pAuditInfo);
	if (rc != ERROR_SUCCESS) {
		LsaClose(hPolicy);
		return (PROBE_ENOVAL);
	}


	if(pAuditInfo->AuditingMode) {
		ULONG		i;
		const char*	audit_account_logon = "AUDIT_NONE";
		const char*	audit_account_management = "AUDIT_NONE";
		const char*	audit_detailed_tracking = "AUDIT_NONE";
		const char*	audit_directory_service_access = "AUDIT_NONE";
		const char*	audit_logon = "AUDIT_NONE";
		const char*	audit_object_access = "AUDIT_NONE";
		const char*	audit_policy_change = "AUDIT_NONE";
		const char*	audit_privilege_use = "AUDIT_NONE";
		const char*	audit_system = "AUDIT_NONE";

		for(i=0;i < pAuditInfo->MaximumAuditEventCount;i++) {
			switch (i) {
			case AuditCategoryLogon:
				audit_logon = expand_audit_options(pAuditInfo->EventAuditingOptions[i]); 
				break;
			case AuditCategoryObjectAccess:
				audit_object_access = expand_audit_options(pAuditInfo->EventAuditingOptions[i]); 
				break;
			case AuditCategoryPrivilegeUse:
				audit_privilege_use = expand_audit_options(pAuditInfo->EventAuditingOptions[i]); 
				break;
			case AuditCategoryDetailedTracking:
				audit_detailed_tracking = expand_audit_options(pAuditInfo->EventAuditingOptions[i]); 
				break;
			case AuditCategoryPolicyChange:
				audit_policy_change = expand_audit_options(pAuditInfo->EventAuditingOptions[i]); 
				break;
			case AuditCategoryAccountManagement:
				audit_account_management = expand_audit_options(pAuditInfo->EventAuditingOptions[i]); 
				break;
			case AuditCategoryDirectoryServiceAccess:
				audit_directory_service_access = expand_audit_options(pAuditInfo->EventAuditingOptions[i]); 
				break;
			case AuditCategoryAccountLogon:
				audit_logon = expand_audit_options(pAuditInfo->EventAuditingOptions[i]); 
				break;
			case AuditCategorySystem:
				audit_system = expand_audit_options(pAuditInfo->EventAuditingOptions[i]); 
				break;
			default:
				dE("bad EventAuditingOptions");
				break;
			}
		}

		ent = probe_item_create(OVAL_WINDOWS_AUDIT_EVENT_POLICY, NULL,
			"account_logon",OVAL_DATATYPE_STRING,audit_account_logon,
			"account_management",OVAL_DATATYPE_STRING,audit_account_management,
			"detailed_tracking",OVAL_DATATYPE_STRING,audit_detailed_tracking,
			"directory_service_access",OVAL_DATATYPE_STRING,audit_directory_service_access,
			"logon",OVAL_DATATYPE_STRING,audit_logon,
			"object_access",OVAL_DATATYPE_STRING,audit_object_access,
			"policy_change",OVAL_DATATYPE_STRING,audit_policy_change,
			"privilege_use",OVAL_DATATYPE_STRING,audit_privilege_use,
			"system",OVAL_DATATYPE_STRING,audit_system,
			NULL);

		probe_item_collect(ctx, ent);

	} else {

		ent = probe_item_create(OVAL_WINDOWS_AUDIT_EVENT_POLICY, NULL,
			"account_logon",OVAL_DATATYPE_STRING,"AUDIT_NONE",
			"account_management",OVAL_DATATYPE_STRING,"AUDIT_NONE",
			"detailed_tracking",OVAL_DATATYPE_STRING,"AUDIT_NONE",
			"directory_service_access",OVAL_DATATYPE_STRING,"AUDIT_NONE",
			"logon",OVAL_DATATYPE_STRING,"AUDIT_NONE",
			"object_access",OVAL_DATATYPE_STRING,"AUDIT_NONE",
			"policy_change",OVAL_DATATYPE_STRING,"AUDIT_NONE",
			"privilege_use",OVAL_DATATYPE_STRING,"AUDIT_NONE",
			"system",OVAL_DATATYPE_STRING,"AUDIT_NONE",
			NULL);

		probe_item_collect(ctx, ent);
	}

	LsaFreeMemory(pAuditInfo);
	
	return 0;
}

const char* expand_audit_options(ULONG options) {
	if(options & POLICY_AUDIT_EVENT_NONE) {
		return "AUDIT_NONE";
	} else if(options & POLICY_AUDIT_EVENT_FAILURE && options & POLICY_AUDIT_EVENT_SUCCESS) {
		return "AUDIT_SUCCESS_FAILURE";
	} else if(options & POLICY_AUDIT_EVENT_FAILURE) {
		return "AUDIT_FAILURE";
	} else if(options & POLICY_AUDIT_EVENT_SUCCESS) {
		return "AUDIT_SUCCESS";
	} else {
		dE("Bad audit_options\n");
		return "AUDIT_NONE";
	}
}
