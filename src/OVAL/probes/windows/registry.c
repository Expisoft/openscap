/**
 * @file   registry.c
 * @brief  registry probe
 * @author "Stefan Gustafsson" <sg@expisoft.com>
 *
 * 2015/10/15 sg@expisoft.com
 *  This probe is able to process an registry_object as defined in OVAL 5.?.
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

oval_schema_version_t over;

// FROM filehash.c
static int mem2hex (uint8_t *mem, size_t mlen, char *str, size_t slen)
{
        const char ch[] = "0123456789abcdef";
        register size_t i;

        if (slen < (mlen * 2) + 1) {
                errno = ENOBUFS;
                return (-1);
        }

        for (i = 0; i < mlen; ++i) {
                str[i*2  ] = ch[(mem[i] & 0xf0) >> 4];
                str[i*2+1] = ch[(mem[i] & 0x0f)];
        }

        str[i*2] = '\0';

        return (0);
}

int probe_main(probe_ctx *ctx, void *arg)
{
	SEXP_t*		probe_in;
	SEXP_t*		ent;
	SEXP_t*		val;
	char*		hive = NULL;
	char*		key = NULL;
	char*		name = NULL;
	HKEY		hHive;
	HKEY		hKey;
	LONG		lStatus;
	DWORD		type;
	DWORD		len;
	void*		data = NULL;
	char*		data_str = NULL;
	char		data_buf[32];

	probe_in = probe_ctx_getobject(ctx);
	if (probe_in == NULL) {
		return PROBE_ENOOBJ;
	}

	over = probe_obj_get_platform_schema_version(probe_in);

	ent = probe_obj_getent(probe_in, "hive", 1);
	if (ent == NULL) {
		return (PROBE_ENOENT);
	}

    val = probe_ent_getval(ent);
    if (val == NULL) {
        dI("%s: no value\n", "hive");
        SEXP_free(ent);
        return (PROBE_ENOVAL);
    }

    hive = SEXP_string_cstr(val);
    SEXP_free(val);
	SEXP_free(ent);

	ent = probe_obj_getent(probe_in, "key", 1);
	if (ent == NULL) {
		oscap_free(hive);
		return (PROBE_ENOENT);
	}

    val = probe_ent_getval(ent);
    if (val == NULL) {
        dI("%s: no value\n", "key");
        SEXP_free(ent);
		oscap_free(hive);
        return (PROBE_ENOVAL);
    }

    key = SEXP_string_cstr(val);
    SEXP_free(val);
    SEXP_free(ent);

	ent = probe_obj_getent(probe_in, "name", 1);
	if (ent == NULL) {
		oscap_free(hive);
		oscap_free(key);
		return (PROBE_ENOENT);
	}

	val = probe_ent_getval(ent);
    if (val == NULL) {
		name = NULL;
	} else {
		name = SEXP_string_cstr(val);
		SEXP_free(val);
		SEXP_free(ent);
	}

	if (strcasecmp(hive,"HKEY_CLASSES_ROOT")==0) {
		hHive = HKEY_CLASSES_ROOT;
	} else if (strcasecmp(hive,"HKEY_CURRENT_CONFIG")==0) {
		hHive = HKEY_CURRENT_CONFIG;
	} else if (strcasecmp(hive,"HKEY_CURRENT_USER")==0) {
		hHive = HKEY_CURRENT_USER;
	} else if (strcasecmp(hive,"HKEY_LOCAL_MACHINE")==0) {
		hHive = HKEY_LOCAL_MACHINE;
	} else if (strcasecmp(hive,"HKEY_USERS")==0) {
		hHive = HKEY_USERS;
	} else {
		oscap_free(hive);
		oscap_free(key);
		oscap_free(name);
		return (PROBE_ENOVAL);
	}

	lStatus = RegOpenKeyEx(hHive,key,0,KEY_READ,&hKey);
	if (lStatus != 0) {
		type = REG_NONE;
	} else {

		lStatus = RegQueryValueEx(hKey,name,NULL,&type,NULL,&len);
		if (lStatus != 0) {
			type = REG_NONE;
		} else {
		
			data = calloc(1,len+1);
			if (data == NULL) {
				oscap_free(hive);
				oscap_free(key);
				oscap_free(name);
				return (PROBE_ENOVAL);
			}

			lStatus = RegQueryValueEx(hKey,name,NULL,&type,data,&len);
			if (lStatus != 0) {
				oscap_free(hive);
				oscap_free(key);
				oscap_free(name);
				return (PROBE_ENOVAL);
			}
		}
	}

	switch(type) {
	case REG_SZ:
	case REG_MULTI_SZ:
	case REG_EXPAND_SZ:
		ent = probe_item_create(OVAL_WINDOWS_REGISTRY, NULL,
			"type",OVAL_DATATYPE_STRING,"string",
			"value", OVAL_DATATYPE_STRING,data,NULL);
		break;
	case REG_BINARY:

		data_str = malloc(2*len+1);

		mem2hex(data,len,data_str,2*len+1);

		ent = probe_item_create(OVAL_WINDOWS_REGISTRY, NULL,
			"datatype",OVAL_DATATYPE_STRING,"binary",
			"value", OVAL_DATATYPE_STRING,data_str,NULL);

		break;
	case REG_DWORD:
		sprintf(data_buf,"%lu",*(LPDWORD)data);

		ent = probe_item_create(OVAL_WINDOWS_REGISTRY, NULL,
			"type",OVAL_DATATYPE_STRING,"reg_dword",
			"value", OVAL_DATATYPE_STRING,data_buf,NULL);
		break;
	case REG_QWORD:
		sprintf(data_buf,"%llu",*(long long*)data);

		ent = probe_item_create(OVAL_WINDOWS_REGISTRY, NULL,
			"type",OVAL_DATATYPE_STRING,"reg_qword",
			"value", OVAL_DATATYPE_STRING,data_buf,NULL);
		break;
	case REG_NONE:
		ent = probe_item_create(OVAL_WINDOWS_REGISTRY, NULL,
			"type",OVAL_DATATYPE_STRING,"none",
			NULL);
		break;
	default:
		free(data);
		oscap_free(hive);
		oscap_free(key);
		oscap_free(name);
		return (PROBE_ENOVAL);
	}

	free(data);
	free(data_str);
	oscap_free(hive);
	oscap_free(key);
	oscap_free(name);

	probe_item_collect(ctx, ent);

	return 0;
}
