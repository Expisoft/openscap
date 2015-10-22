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

#define DOWN	0
#define UP		1

int  collect_registry(probe_ctx *ctx,HKEY hHive,const char* key,const char* name);
int  expand_registry(HKEY hHive,SEXP_t* list,const char* key,const char* name,int recurse_direction,int max_depth);		
void split_reg(const char* reg_item,char** reg_key,char** reg_name);

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
	int			hive_op = OVAL_OPERATION_EQUALS;
	char*		key = NULL;
	int			key_op = OVAL_OPERATION_EQUALS;
	char*		name = NULL;
	int			name_op = OVAL_OPERATION_EQUALS;
	HKEY		hHive;
	int			rc;
	SEXP_t*		registry_list;
	int			len,i;

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

	hive_op = probe_ent_getoperation(ent,OVAL_OPERATION_EQUALS);

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

	key_op = probe_ent_getoperation(ent,OVAL_OPERATION_EQUALS);

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
	}
	
	name_op = probe_ent_getoperation(ent,OVAL_OPERATION_EQUALS);

	SEXP_free(ent);

	if (hive_op != OVAL_OPERATION_EQUALS) {
		dE("Unsupported hive operation\n");
		oscap_free(hive);
		oscap_free(key);
		oscap_free(name);
		return (PROBE_ENOVAL);
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

	if (key_op == OVAL_OPERATION_PATTERN_MATCH || name_op == OVAL_OPERATION_PATTERN_MATCH) {
		SEXP_t*	behaviors;
		int		max_depth = -1;
		int		recurse_direction = DOWN;

		behaviors = probe_obj_getent(probe_in, "behaviors", 1);
		if (behaviors) {

			val = probe_ent_getattrval(behaviors, "recurse_direction");
			if (val) {
				if (SEXP_strcmp(val,"up")) {
					recurse_direction  = UP;
				} else if (SEXP_strcmp(val,"down")) {
					recurse_direction  = DOWN;
				} else {
					dE("bad value for recurse_direction\n");
					oscap_free(hive);
					oscap_free(key);
					oscap_free(name);
					return (PROBE_ENOVAL);
				}
			}

			val = probe_ent_getattrval(behaviors, "max_depth");
			if (val) {
				max_depth = SEXP_number_getb(val);
			}
		}

		registry_list = SEXP_list_new(NULL);

		rc = expand_registry(hHive,registry_list,key,name,recurse_direction,max_depth);		
		if (rc) {
			oscap_free(hive);
			oscap_free(key);
			oscap_free(name);
			return rc;
		}

		/* Now collect the resulting registry values */
		len = SEXP_list_length(registry_list);
		if (len == -1) {
			return (PROBE_EINVAL);
		}

		for(i=0;i<len;i++) {
			char*	reg_item;
			SEXP_t*	item;
			char*	reg_key;
			char*	reg_name;

			item = SEXP_list_nth(registry_list,i+1);
			if (item == NULL) {
				continue;
			}

			reg_item = SEXP_string_cstr(item);
			SEXP_free(item);

			split_reg(reg_item,&reg_key,&reg_name);

			collect_registry(ctx,hHive,reg_key,reg_name);

			free(reg_key);
			free(reg_name);

			oscap_free(reg_item);
		}

		SEXP_free(registry_list);

	} else {
		rc = collect_registry(ctx,hHive,key,name);
		if (rc) {
			oscap_free(hive);
			oscap_free(key);
			oscap_free(name);
			return rc;
		}
	}

	oscap_free(hive);
	oscap_free(key);
	oscap_free(name);

	return 0;
}

int collect_registry(probe_ctx *ctx,HKEY hHive,const char* key,const char* name) {
	HKEY		hKey;
	LONG		lStatus;
	DWORD		type;
	DWORD		len = 0;
	void*		data = NULL;
	char*		data_str = NULL;
	char		data_buf[32];
	char*		data_val;
	SEXP_t*		ent;

	lStatus = RegOpenKeyEx(hHive,key,0,KEY_READ|KEY_WOW64_64KEY,&hKey);
	if (lStatus != 0) {

		ent = probe_item_create(
				OVAL_WINDOWS_REGISTRY, NULL,
				"type", OVAL_DATATYPE_STRING, "reg_none",
				NULL
		);

		probe_item_setstatus(ent, SYSCHAR_STATUS_DOES_NOT_EXIST);
		probe_item_add_msg(ent, OVAL_MESSAGE_LEVEL_ERROR,"RegOpenKeyEx %08x",lStatus);
		
		probe_item_collect(ctx, ent);

		return(0);
	} 

	lStatus = RegQueryValueEx(hKey,name,NULL,&type,NULL,&len);
	if (lStatus != 0) {
		ent = probe_item_create(
				OVAL_WINDOWS_REGISTRY, NULL,
				"type", OVAL_DATATYPE_STRING, "reg_none",
				"key", OVAL_DATATYPE_STRING, key,
				"name", OVAL_DATATYPE_STRING, name,
				NULL
		);

		probe_item_setstatus(ent, SYSCHAR_STATUS_DOES_NOT_EXIST);
		probe_item_add_msg(ent, OVAL_MESSAGE_LEVEL_ERROR,"RegQueryValueEx %08x",lStatus);
		
		probe_item_collect(ctx, ent);

		return(0);
	} 

	data = calloc(1,len+1);
	if (data == NULL) {
		return (PROBE_ENOVAL);
	}

	lStatus = RegQueryValueEx(hKey,name,NULL,&type,data,&len);
	if (lStatus != 0) {
		dE("RegQueryValueEx\n");
		return (PROBE_ENOVAL);
	}

	switch(type) {
	case REG_SZ:
		ent = probe_item_create(OVAL_WINDOWS_REGISTRY, NULL,
			"type",OVAL_DATATYPE_STRING,"reg_sz",
			"value", OVAL_DATATYPE_STRING,data,NULL);
		break;
	case REG_MULTI_SZ:
		ent = probe_item_create(OVAL_WINDOWS_REGISTRY, NULL,
			"type",OVAL_DATATYPE_STRING,"reg_multi_sz",
			NULL);

		data_val = data;
		if (!*data_val) {
			SEXP_t	ti;

			probe_item_ent_add(ent,"value", NULL,SEXP_string_new_r(&ti,"",0));
		} else {
			for (; *data_val; data_val += strlen(data_val) + 1) {
				SEXP_t	ti;

				probe_item_ent_add(ent,"value", NULL,SEXP_string_new_r(&ti,data_val,strlen(data_val)));
			}
		}
		break;
	case REG_EXPAND_SZ:
		ent = probe_item_create(OVAL_WINDOWS_REGISTRY, NULL,
			"type",OVAL_DATATYPE_STRING,"reg_expand_sz",
			"value", OVAL_DATATYPE_STRING,data,NULL);
		break;
	case REG_BINARY:

		data_str = malloc(2*len+1);

		mem2hex(data,len,data_str,2*len+1);

		ent = probe_item_create(OVAL_WINDOWS_REGISTRY, NULL,
			"type",OVAL_DATATYPE_STRING,"reg_binary",
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
			"type",OVAL_DATATYPE_STRING,"reg_none",
			NULL);
		break;
	default:
		free(data);
		return (PROBE_ENOVAL);
	}

	free(data);
	free(data_str);

	probe_item_collect(ctx, ent);

	return 0;
}

void split_reg(const char* reg_item,char** reg_key,char** reg_name) {
	char*	p;

	p = strchr(reg_item,':');
	if (p == NULL) {
		*reg_key = strdup(reg_item);
		*reg_name = NULL;
	} else {
		*reg_key = strndup(reg_item,p-reg_item);
		*reg_name = strdup(p+1);
	}
}

int expand_registry(HKEY hHive,SEXP_t* list,const char* key,const char* name,int recurse_direction,int max_depth) {
	return 0;
}
