/**
 * @file   lockoutpolicy.c
 * @brief  lockoutpolicy probe
 * @author "Stefan Gustafsson" <sg@expisoft.com>
 *
 * 2015/10/15 sg@expisoft.com
 *  This probe is able to process an lockoutpolicy as defined in OVAL 5.?.
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
	SEXP_t*				ent;
	USER_MODALS_INFO_0*	pModal0 = NULL;
	USER_MODALS_INFO_3*	pModal3 = NULL;
	NET_API_STATUS		rc;

	/*
	 * Pick up the system modal settings, level 0
	 */
	rc = NetUserModalsGet(NULL,0,(LPBYTE *)&pModal0);
	if (rc != NERR_Success) {
		dE("NetUserModalsGet 0 failed %d\n",rc);
		return (PROBE_ENOVAL);
	}

	/*
	 * Pick up the system modal settings, level 3
	 */
	rc = NetUserModalsGet(NULL,3,(LPBYTE *)&pModal3);
	if (rc != NERR_Success) {
		dE("NetUserModalsGet 3 failed %d\n",rc);
		return (PROBE_ENOVAL);
	}

	dI("lockoutpolicy: %d %d %d %d\n",pModal0->usrmod0_force_logoff,pModal3->usrmod3_lockout_duration,pModal3->usrmod3_lockout_observation_window,pModal3->usrmod3_lockout_threshold);

	/*
     * Create the result node
	 */
	ent = probe_item_create(OVAL_WINDOWS_LOCKOUT_POLICY, NULL,
		"force_logoff",OVAL_DATATYPE_INTEGER,(uint64_t)pModal0->usrmod0_force_logoff,
		NULL);
	probe_item_collect(ctx, ent);

	ent = probe_item_create(OVAL_WINDOWS_LOCKOUT_POLICY, NULL,
		"lockout_duration",OVAL_DATATYPE_INTEGER,(uint64_t)pModal3->usrmod3_lockout_duration,
		NULL);
	probe_item_collect(ctx, ent);

	ent = probe_item_create(OVAL_WINDOWS_LOCKOUT_POLICY, NULL,
		"lockout_observation_window",OVAL_DATATYPE_INTEGER,(uint64_t)pModal3->usrmod3_lockout_observation_window,
		NULL);
	probe_item_collect(ctx, ent);

	ent = probe_item_create(OVAL_WINDOWS_LOCKOUT_POLICY, NULL,
		"lockout_threshold",OVAL_DATATYPE_INTEGER,(int64_t)pModal3->usrmod3_lockout_threshold,
		NULL);
	probe_item_collect(ctx, ent);

	NetApiBufferFree(pModal0);
	NetApiBufferFree(pModal3);

	return 0;
}
