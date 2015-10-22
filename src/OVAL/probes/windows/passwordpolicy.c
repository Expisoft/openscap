/**
 * @file   passwordpolicy.c
 * @brief  passwordpolicy probe
 * @author "Stefan Gustafsson" <sg@expisoft.com>
 *
 * 2015/10/15 sg@expisoft.com
 *  This probe is able to process an passwordpolicy as defined in OVAL 5.?.
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
#include <lm.h>

int probe_main(probe_ctx *ctx, void *arg)
{
	SEXP_t*					ent;
	USER_MODALS_INFO_0*		pModalInfo = NULL;
	NET_API_STATUS			rc;
	bool					password_complexity = true;
	bool					reversible_encryption = false;

	rc = NetUserModalsGet(NULL,0,(LPBYTE*)&pModalInfo);
	if (rc != NERR_Success) {
		return 0;
	}

	/*
	 * Locate password_complexity and reversible_encryption by dumping out the security policy to file
	 */
#if 0
	if((rc = system("secedit.exe /export /quiet /areas SECURITYPOLICY /cfg c:\\temp\\secedit.ini")) != 0) {
		dE("passwordpolicy: Failed to exec secedit.exe\n");
	} else {
		rc = GetPrivateProfileInt("System Access","PasswordComplexity",2,"c:\\temp\\secedit.ini");
		switch(rc) {
			case 0:
				password_complexity = false;
				break;
			case 1:
				password_complexity = true;
				break;
			default:
				dE("passwordpolicy: Failed to get PasswordComplexity value\n");
				break;
		}

		rc = GetPrivateProfileInt("System Access","ClearTextPassword",2,"c:\\temp\\secedit.ini");
		switch(rc) {
			case 0:
				reversible_encryption = false;
				break;
			case 1:
				reversible_encryption = true;
				break;
			default:
				dE("passwordpolicy: Failed to get PasswordComplexity value\n");
				break;
		}
	}
#endif

	ent = probe_item_create(OVAL_WINDOWS_PASSWORD_POLICY, NULL,
		"max_passwd_age",OVAL_DATATYPE_INTEGER,(uint64_t)pModalInfo->usrmod0_max_passwd_age,
		"min_passwd_age",OVAL_DATATYPE_INTEGER,(uint64_t)pModalInfo->usrmod0_min_passwd_age,
		"min_passwd_len",OVAL_DATATYPE_INTEGER,(uint64_t)pModalInfo->usrmod0_min_passwd_len,
		"password_hist_len",OVAL_DATATYPE_INTEGER,(uint64_t)pModalInfo->usrmod0_password_hist_len,
		"password_complexity",OVAL_DATATYPE_BOOLEAN,password_complexity,
		"reversible_encryption",OVAL_DATATYPE_BOOLEAN,reversible_encryption,
		NULL);
	probe_item_collect(ctx, ent);

	NetApiBufferFree(pModalInfo);

	return 0;
}
