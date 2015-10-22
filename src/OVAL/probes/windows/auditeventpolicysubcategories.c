/**
 * @file   auditeventpolicysubcategories.c
 * @brief  auditeventpolicysubcategories probe
 * @author "Stefan Gustafsson" <sg@expisoft.com>
 *
 * 2015/10/15 sg@expisoft.com
 *  This probe is able to process an auditeventpolicysubcategories as defined in OVAL 5.?.
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

#define _WIN32_WINNT	0x0600

#include <windows.h>
#include <ntsecapi.h>

const char* expand_audit_options(ULONG options);
char* GuidToString(GUID* guid);

struct AuditPolicySubcatagory {
	const char*	guid;
	const char*	name;
	const char*	value;
};

char* GuidToString(GUID* guid) {
	char*	res;

	res = calloc(1,40);
	if (!res) {
		return res;
	}

	// Use sprintf to convert GUID to make sure we get it in same format as we have in out table
	sprintf(res, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",(UINT)guid->Data1,guid->Data2,guid->Data3,guid->Data4[0],guid->Data4[1],guid->Data4[2],guid->Data4[3],guid->Data4[4],guid->Data4[5],guid->Data4[6],guid->Data4[7]);

	return res;
}

int probe_main(probe_ctx *ctx, void *arg)
{
	SEXP_t*						ent;
	LSA_OBJECT_ATTRIBUTES		oa;
	NTSTATUS					rc;
	LSA_HANDLE					hPolicy;
	PPOLICY_AUDIT_EVENTS_INFO	pAuditInfo = NULL;
	ULONG						i,y,z;

	struct AuditPolicySubcatagory aAuditPolicySubcatagoryList[] = {
		{"{0CCE923F-69AE-11D9-BED3-505054503030}", "credential_validation","AUDIT_NONE"},
		{"{0CCE9240-69AE-11D9-BED3-505054503030}", "kerberos_service_ticket_operations","AUDIT_NONE"},
		{"{0CCE9242-69AE-11D9-BED3-505054503030}", "kerberos_authentication_service","AUDIT_NONE"},
		{"{0CCE9241-69AE-11D9-BED3-505054503030}", "other_account_logon_events","AUDIT_NONE"},
		{"{0CCE9239-69AE-11D9-BED3-505054503030}", "application_group_management","AUDIT_NONE"},
		{"{0CCE9236-69AE-11D9-BED3-505054503030}", "computer_account_management","AUDIT_NONE"},
		{"{0CCE9238-69AE-11D9-BED3-505054503030}", "distribution_group_management","AUDIT_NONE"},
		{"{0CCE923A-69AE-11D9-BED3-505054503030}", "other_account_management_events","AUDIT_NONE"},
		{"{0CCE9237-69AE-11D9-BED3-505054503030}", "security_group_management","AUDIT_NONE"},
		{"{0CCE9235-69AE-11D9-BED3-505054503030}", "user_account_management","AUDIT_NONE"},
		{"{0CCE922D-69AE-11D9-BED3-505054503030}", "dpapi_activity","AUDIT_NONE"},
		{"{0CCE922B-69AE-11D9-BED3-505054503030}", "process_creation","AUDIT_NONE"},
		{"{0CCE922C-69AE-11D9-BED3-505054503030}", "process_termination","AUDIT_NONE"},
		{"{0CCE922E-69AE-11D9-BED3-505054503030}", "rpc_events","AUDIT_NONE"},
		{"{0CCE923B-69AE-11D9-BED3-505054503030}", "directory_service_access","AUDIT_NONE"},
		{"{0CCE923C-69AE-11D9-BED3-505054503030}", "directory_service_changes","AUDIT_NONE"},
		{"{0CCE923D-69AE-11D9-BED3-505054503030}", "directory_service_replication","AUDIT_NONE"},
		{"{0CCE923E-69AE-11D9-BED3-505054503030}", "detailed_directory_service_replication","AUDIT_NONE"},
		{"{0CCE9215-69AE-11D9-BED3-505054503030}", "logon","AUDIT_NONE"},
		{"{0CCE9216-69AE-11D9-BED3-505054503030}", "logoff","AUDIT_NONE"}, 
		{"{0CCE9217-69AE-11D9-BED3-505054503030}", "account_lockout","AUDIT_NONE"},
		{"{0CCE9218-69AE-11D9-BED3-505054503030}", "ipsec_main_mode","AUDIT_NONE"},
		{"{0CCE9219-69AE-11D9-BED3-505054503030}","ipsec_quick_mode","AUDIT_NONE"},
		{"{0CCE921A-69AE-11D9-BED3-505054503030}", "ipsec_extended_mode","AUDIT_NONE"},
		{"{0CCE921B-69AE-11D9-BED3-505054503030}", "special_logon","AUDIT_NONE"},
		{"{0CCE921C-69AE-11D9-BED3-505054503030}", "other_logon_logoff_events","AUDIT_NONE"},
		{"{0CCE9243-69AE-11D9-BED3-505054503030}", "network_policy_server","AUDIT_NONE"},
		{"{0CCE921D-69AE-11D9-BED3-505054503030}", "file_system","AUDIT_NONE"},
		{"{0CCE921E-69AE-11D9-BED3-505054503030}", "registry","AUDIT_NONE"},
		{"{0CCE921F-69AE-11D9-BED3-505054503030}", "kernel_object","AUDIT_NONE"},
		{"{0CCE9220-69AE-11D9-BED3-505054503030}", "sam","AUDIT_NONE"},
		{"{0CCE9221-69AE-11D9-BED3-505054503030}", "certification_services","AUDIT_NONE"},
		{"{0CCE9222-69AE-11D9-BED3-505054503030}", "application_generated","AUDIT_NONE"},
		{"{0CCE9223-69AE-11D9-BED3-505054503030}", "handle_manipulation","AUDIT_NONE"},
		{"{0CCE9224-69AE-11D9-BED3-505054503030}", "file_share","AUDIT_NONE"},
		{"{0CCE9225-69AE-11D9-BED3-505054503030}", "filtering_platform_packet_drop","AUDIT_NONE"},
		{"{0CCE9226-69AE-11D9-BED3-505054503030}", "filtering_platform_connection","AUDIT_NONE"},
		{"{0CCE9227-69AE-11D9-BED3-505054503030}", "other_object_access_events","AUDIT_NONE"},
		{"{0CCE9244-69AE-11D9-BED3-505054503030}", "detailed_file_share","AUDIT_NONE"},
		/// {0CCE9245-69AE-11D9-BED3-505054503030}	Removable Storage
		// {0CCE9246-69AE-11D9-BED3-505054503030} Central Policy Staging                    
		{"{0CCE922F-69AE-11D9-BED3-505054503030}", "audit_policy_change","AUDIT_NONE"}, 
		{"{0CCE9230-69AE-11D9-BED3-505054503030}", "authentication_policy_change","AUDIT_NONE"},
		{"{0CCE9231-69AE-11D9-BED3-505054503030}", "authorization_policy_change","AUDIT_NONE"},
		{"{0CCE9232-69AE-11D9-BED3-505054503030}", "mpssvc_rule_level_policy_change","AUDIT_NONE"},
		{"{0CCE9233-69AE-11D9-BED3-505054503030}", "filtering_platform_policy_change","AUDIT_NONE"}, 
		{"{0CCE9234-69AE-11D9-BED3-505054503030}", "other_policy_change_events","AUDIT_NONE"},	
		{"{0CCE9228-69AE-11D9-BED3-505054503030}", "sensitive_privilege_use","AUDIT_NONE"},
		{"{0CCE9229-69AE-11D9-BED3-505054503030}", "non_sensitive_privilege_use","AUDIT_NONE"},
		{"{0CCE922A-69AE-11D9-BED3-505054503030}", "other_privilege_use_events","AUDIT_NONE"},
		{"{0CCE9210-69AE-11D9-BED3-505054503030}", "security_state_change","AUDIT_NONE"},
		{"{0CCE9211-69AE-11D9-BED3-505054503030}", "security_system_extension","AUDIT_NONE"},
		{"{0CCE9212-69AE-11D9-BED3-505054503030}", "system_integrity","AUDIT_NONE"},
		{"{0CCE9213-69AE-11D9-BED3-505054503030}", "ipsec_driver","AUDIT_NONE"},
		{"{0CCE9214-69AE-11D9-BED3-505054503030}", "other_system_events","AUDIT_NONE"},
		{NULL,NULL,NULL}};

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

		for(i=0;i < pAuditInfo->MaximumAuditEventCount;i++) {
			GUID						guidCategoryId;
			GUID*						pSubCategory = NULL;
			ULONG						nSubCategory = 0;
			PAUDIT_POLICY_INFORMATION	pAuditPolicies = NULL;

			if (!AuditLookupCategoryGuidFromCategoryId((POLICY_AUDIT_EVENT_TYPE)i, &guidCategoryId)) {
				dE("AuditLookupCategoryGuidFromCategoryId failed\n");
				LsaClose(hPolicy);
				return (PROBE_ENOVAL);
			}

			if (!AuditEnumerateSubCategories(&guidCategoryId, FALSE, &pSubCategory, &nSubCategory)) {
				dE("AuditEnumerateSubCategories failed\n");
				LsaClose(hPolicy);
				return (PROBE_ENOVAL);
			}

			if (!AuditQuerySystemPolicy(pSubCategory, nSubCategory, &pAuditPolicies)) {
				dE("AuditQuerySystemPolicy failed\n");
				LsaClose(hPolicy);
				return (PROBE_ENOVAL);
			}

			for(y = 0; y < nSubCategory; y++) {
				char*						pszGuid;

				pszGuid = GuidToString(&pAuditPolicies[y].AuditSubCategoryGuid);

				for(z=0;aAuditPolicySubcatagoryList[z].guid!=NULL;z++) {
					if (strcmp(aAuditPolicySubcatagoryList[z].guid,pszGuid)==0) {
						aAuditPolicySubcatagoryList[z].value = expand_audit_options(pAuditPolicies[y].AuditingInformation);
					}
				}
			}
		}
	} 

	/*
     * Return the list of subcategories
	 */

	ent = probe_item_create(OVAL_WINDOWS_AUDIT_EVENT_POLICY_SUBCATEGORIES, NULL,NULL);

	for(i=0;aAuditPolicySubcatagoryList[i].guid!=NULL;i++) {
		SEXP_t	ti;

		probe_item_ent_add(ent,aAuditPolicySubcatagoryList[i].name, NULL,SEXP_string_new_r(&ti,aAuditPolicySubcatagoryList[i].value,strlen(aAuditPolicySubcatagoryList[i].value)));

	}

	probe_item_collect(ctx, ent);

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
