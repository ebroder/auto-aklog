/*
 *  afs_princ.c
 *  auto-aklog
 *
 *  Created by Evan Broder on 1/30/09.
 *
 */

#include "afs_princ.h"
#include "k4name_parse.h"

#include <krb5/krb5.h>
#include <kerberosIV/krb.h>
#include <com_err.h>

#include <afs/stds.h>
#include <afs/com_err.h>
#include <afs/ptuser.h>
#include <afs/dirpath.h>
#include <afs/cellconfig.h>
#include <afs/param.h>
#include <afs/auth.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

int afs_princ(char ** princ) {
	int code;
	
	krb5_context context;
	
	char confdir[AFSDIR_PATH_MAX];
	struct afsconf_dir *tdir;
	char cellstr[64];
	struct afsconf_cell cellconfig;
	
	struct ktc_principal serviceName, clientName;
	struct ktc_token token;
	afs_int32 pts_id;
	char afs_name[PR_MAXNAMELEN];
	char k4name[ANAME_SZ] = "\0", k4inst[INST_SZ] = "\0", k4realm[REALM_SZ] = "\0";
	krb5_principal k5princ;
	
	char ** hrealms = NULL;
	char * chunk;
	
	initialize_ktc_error_table();
	initialize_krb_error_table();
	initialize_acfg_error_table();
	
	code = krb5_init_context(&context);
	if (code)
		return code;
	
	// Get some config information
	strlcpy(confdir, AFSDIR_CLIENT_ETC_DIRPATH, sizeof(confdir));
	tdir = afsconf_Open(confdir);
	if (!tdir)
		return AFSCONF_FAILURE;
	
	// Find out what ThisCell is
	code = afsconf_GetLocalCell(tdir, cellstr, sizeof(cellstr));
	if (code)
		return code;
	
	// Get information about ThisCell (not for now - we'll need it later)
	code = afsconf_GetCellInfo(tdir, cellstr, NULL, &cellconfig);
	if (code)
		return code;
	
	// Specify the service we want tokens for
	strlcpy(serviceName.cell, cellstr, sizeof(serviceName.cell));
	serviceName.instance[0] = 0;
	strlcpy(serviceName.name, "afs", sizeof(serviceName.name));
	
	// Get the token for ThisCell (mostly so we can get the client principal)
	code = ktc_GetToken(&serviceName, &token, sizeof(token), &clientName);
	if (code)
		return code;
	
	// See if this is a "normal" looking token. If it's not, give up.
	if (strncmp(clientName.name, "AFS ID", 6) != 0)
		return -EINVAL;
	
	// "normal" tokens are of the form "AFS ID 12345". Grab the 12345.
	pts_id = atoi((clientName.name + 7));
	
	// Connect to the PRDB
	code = pr_Initialize(0, confdir, cellstr);
	if (code)
		return code;
	
	// Convert the PTS ID to a "AFS principal"
	code = pr_SIdToName(pts_id, afs_name);
	pr_End();
	
	chunk = strchr(afs_name, '@');
	// If there's an @ in the "AFS principal", uppercase the realm
	if (chunk) {
		for (; *chunk; chunk++) {
			*chunk = toupper(*chunk);
		}
	}
	// If there's no realm, get the Kerberos realm for the cell
	else {
		// Get the realm corresponding to the first DB server
		code = krb5_get_host_realm(context, cellconfig.hostName[0], &hrealms);
		if (code)
			return code;
		
		strncat(afs_name, "@", sizeof(afs_name));
		strncat(afs_name, hrealms[0], sizeof(afs_name));
		
		krb5_free_host_realm(context, hrealms);
	}
	
	code = k4name_parse(k4name, k4inst, k4realm, afs_name);
	if (code)
		return code;
	
	code = krb5_425_conv_principal(context, k4name, k4inst, k4realm, &k5princ);
	if (code)
		return code;
	
	code = krb5_unparse_name(context, k5princ, princ);
	if (code)
		return code;
	
	krb5_free_principal(context, k5princ);
	afsconf_Close(tdir);
	krb5_free_context(context);

	return 0;
}
