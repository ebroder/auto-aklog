//
//  auto-aklog.m
//  auto-aklog
//
//  Created by Evan Broder on 12/13/07.
//  Copyright (c) Evan Broder, 2008
//

#include "afs_princ.h"
#import <Kerberos/KLLoginLogoutNotification.h>
#import <Kerberos/CredentialsCache.h>
#include <afs/stds.h>
#include <afs/auth.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

KLStatus KerberosLoginNotification_InitializePlugin(
	KLN_APIVersion inAPIVersion)
{
	if (inAPIVersion == kKLN_APIVersion_1)
	{
		return noErr;
	}
	else
	{
		return paramErr;
	}
}


KLStatus KerberosLoginNotification_Login(
	KLN_LoginType inLoginType,
	const char * inCredentialsCache)
{
	pid_t pid;
	
	if(0 == (pid = fork())) {
		setenv("KRB5CCNAME", inCredentialsCache, TRUE);
		if(execlp("/Library/Kerberos Plug-Ins/auto-aklog.loginLogout/Contents/MacOS/maybe_aklog", "maybe_aklog", (char *) 0)) {
			perror("maybe_aklog");
			exit(1);
		}
	} else {
		waitpid(pid, NULL, 0);
	}

    return 0;
}

void KerberosLoginNotification_Logout(
	const char* inCredentialsCache)
{
}
