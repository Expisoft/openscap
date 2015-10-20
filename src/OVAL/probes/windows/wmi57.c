/**
 * @file   wmi57.c
 * @brief  WMI 5.7 probe
 * @author "Stefan Gustafsson" <sg@expisoft.com>
 *
 * 2015/10/19 sg@expisoft.com
 *  First version of WMI probe
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
#include <wbemidl.h>

void comError(probe_ctx *ctx,const char* func,HRESULT hr);

oval_schema_version_t over;

void comError(probe_ctx *ctx,const char* func,HRESULT hr) {
	SEXP_t*			item;

	dE("wmi57: COM error %s %08x\n",func,hr);

	item = probe_item_create(
			OVAL_WINDOWS_WMI_57, NULL,
			"result", OVAL_DATATYPE_STRING, "",
			NULL
	);

	probe_item_setstatus(item, SYSCHAR_STATUS_ERROR);
	probe_item_add_msg(item, OVAL_MESSAGE_LEVEL_ERROR,"COM error from %s : %08x",func,hr);
	probe_item_collect(ctx, item);
}

int probe_main(probe_ctx *ctx, void *arg)
{
	SEXP_t*					probe_in;
	SEXP_t*					ent;
	SEXP_t*					val;
	char*					ns = NULL;
	char*					wql = NULL;
	HRESULT					hr;
	BSTR					b_ns;
	BSTR					b_wql;
	int						wslen;
	IWbemLocator*			pLocator = NULL;
	IWbemServices*			pService = NULL;
	IEnumWbemClassObject*	pEnumerator = NULL;
	IWbemClassObject*		pclsObj = NULL;
	ULONG					uReturn = 0;
	int						nResult;

	probe_in = probe_ctx_getobject(ctx);
	if (probe_in == NULL) {
		return PROBE_ENOOBJ;
	}

	over = probe_obj_get_platform_schema_version(probe_in);

	ent = probe_obj_getent(probe_in, "namespace", 1);
	if (ent == NULL) {
        dI("%s: not found\n", "namespace");
		return (PROBE_ENOENT);
	}

    val = probe_ent_getval(ent);
    if (val == NULL) {
        dI("%s: no value\n", "namespace");
        SEXP_free(ent);
        return (PROBE_ENOVAL);
    }

    ns = SEXP_string_cstr(val);
    SEXP_free(val);
	SEXP_free(ent);

	ent = probe_obj_getent(probe_in, "wql", 1);
	if (ent == NULL) {
        dI("%s: not found\n", "wql");
		oscap_free(ns);
		return (PROBE_ENOENT);
	}

    val = probe_ent_getval(ent);
    if (val == NULL) {
        dI("%s: no value\n", "wql");
        SEXP_free(ent);
		oscap_free(ns);
        return (PROBE_ENOVAL);
    }

    wql = SEXP_string_cstr(val);
    SEXP_free(val);
    SEXP_free(ent);

	dI("wmi57: %s %s\n",ns,wql);

	wslen = MultiByteToWideChar(CP_ACP, 0, ns, strlen(ns), 0, 0);

    b_ns = SysAllocStringLen(0, wslen);

    MultiByteToWideChar(CP_ACP, 0, ns, strlen(ns), b_ns, wslen);

	wslen = MultiByteToWideChar(CP_ACP, 0, wql, strlen(wql), 0, 0);

    b_wql = SysAllocStringLen(0, wslen);

    MultiByteToWideChar(CP_ACP, 0, wql, strlen(wql), b_wql, wslen);


	// Initialize COM. ------------------------------------------
	hr =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hr)) {
		comError(ctx,"CoInitializeEx",hr);
		SysFreeString(b_ns);
		SysFreeString(b_wql);
		oscap_free(ns);
		oscap_free(wql);
		return (PROBE_ENOVAL);
    }
	/*
	 * Create WbemLocator class
	 */
	hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *) &pLocator);
	if (FAILED(hr)) {
		comError(ctx,"CoCreateInstance",hr);
		SysFreeString(b_ns);
		SysFreeString(b_wql);
		oscap_free(ns);
		oscap_free(wql);
		return (PROBE_ENOVAL);
	}

	// Connect to WMI through the IWbemLocator::ConnectServer method
	hr = pLocator->lpVtbl->ConnectServer(pLocator,b_ns, NULL, NULL, 0, 0, 0, 0, &pService);
	if (FAILED(hr)) {
		comError(ctx,"ConnectServer",hr);
		SysFreeString(b_ns);
		SysFreeString(b_wql);
		oscap_free(ns);
		oscap_free(wql);
		return (PROBE_ENOVAL);
	}

	// Set security levels on the proxy -------------------------	
	hr = CoSetProxyBlanket((IUnknown*)pService, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hr)) {
		comError(ctx,"CoSetProxyBlanket",hr);
		SysFreeString(b_ns);
		SysFreeString(b_wql);
		oscap_free(ns);
		oscap_free(wql);
		return (PROBE_ENOVAL);
	}

	// Use the IWbemServices pointer to make requests of WMI
	hr = pService->lpVtbl->ExecQuery(pService,L"WQL",b_wql, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hr)) {
		comError(ctx,"ExecQuery",hr);
		SysFreeString(b_ns);
		SysFreeString(b_wql);
		oscap_free(ns);
		oscap_free(wql);
		return (PROBE_ENOVAL);
	}

	ent = NULL;

	for(nResult=0;;) {

		hr = pEnumerator->lpVtbl->Next(pEnumerator,WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if((uReturn == 0) || (hr == WBEM_S_FALSE)) {
			break;
		} 
		if (hr) {
			comError(ctx,"Next",hr);
			break;
		}

		
		hr = pclsObj->lpVtbl->BeginEnumeration(pclsObj, WBEM_FLAG_NONSYSTEM_ONLY);
		if (hr) {
			comError(ctx,"BeginEnumeration",hr);
			break;
		}

		for(;;) {
			BSTR	bName = NULL;
			VARIANT	vtProp;
			char*	result = NULL;

			VariantInit(&vtProp);

			hr = pclsObj->lpVtbl->Next(pclsObj,0,&bName,&vtProp,NULL,NULL);
			if (hr == WBEM_S_NO_MORE_DATA) {
				break;
			}
			if (hr) {
				comError(ctx,"Next",hr);
				break;
			}

			if ((V_VT(&vtProp) == VT_BSTR)) {
				int	alen;

				alen = WideCharToMultiByte(CP_ACP, 0, vtProp.bstrVal, -1, 0, 0,NULL,NULL);
				if (!alen) {
					return (PROBE_ENOVAL);
				}

				result = malloc(alen);
				if (result == NULL) {
					return (PROBE_ENOVAL);
				}

				alen = WideCharToMultiByte(CP_ACP, 0, vtProp.bstrVal, -1, result, alen,NULL,NULL);

			} else if ((V_VT(&vtProp) == VT_UINT) || (V_VT(&vtProp) == VT_INT)) {
				int value = V_INT(&vtProp);

				result = malloc(32);
				if (result == NULL) {
					return (PROBE_ENOVAL);
				}

				sprintf(result,"%d",value);

			} else if ((V_VT(&vtProp) == VT_BOOL)) {
				if ( V_BOOL(&vtProp) == VARIANT_TRUE ){
					result = strdup("true");
				}else{
					result = strdup("false");
				}
			} else if ((V_VT(&vtProp) == VT_I1)) {
				char value = V_I1(&vtProp);

				result = malloc(32);
				if (result == NULL) {
					return (PROBE_ENOVAL);
				}

				sprintf(result,"%c",value);

			} else if ((V_VT(&vtProp) == VT_I2)) {
				int value = V_I2(&vtProp);

				result = malloc(32);
				if (result == NULL) {
					return (PROBE_ENOVAL);
				}

				sprintf(result,"%d",value);

			} else if ((V_VT(&vtProp) == VT_I4)) {
				long value = V_I4(&vtProp);

				result = malloc(32);
				if (result == NULL) {
					return (PROBE_ENOVAL);
				}

				sprintf(result,"%ld",value);
			} else if ((V_VT(&vtProp) == VT_NULL)) {
				result = strdup("null");
			} else {
				result = strdup("unsupported VT type");
			}

			dI("wmi57: result %S %s\n",bName,result);

			ent = probe_item_create(OVAL_WINDOWS_WMI, NULL,
				"result",OVAL_DATATYPE_STRING,result,
				NULL);
			
			SysFreeString(bName);
			VariantClear(&vtProp);
			free(result);

			probe_item_collect(ctx, ent);
		} 
		
		nResult++;

		pclsObj->lpVtbl->Release(pclsObj);
	}

	// Create empty result if not result returned
	if (!nResult) {
		ent = probe_item_create(OVAL_WINDOWS_WMI_57, NULL,
			"result",OVAL_DATATYPE_STRING,"",
			NULL);
		probe_item_collect(ctx, ent);
	}

	pEnumerator->lpVtbl->Release(pEnumerator);
	pService->lpVtbl->Release(pService);
	pLocator->lpVtbl->Release(pLocator);

	SysFreeString(b_ns);
	SysFreeString(b_wql);
	oscap_free(ns);
	oscap_free(wql);

	return 0;
}
