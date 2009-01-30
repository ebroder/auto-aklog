//
//  auto-aklog.m
//  auto-aklog
//
//  Created by Evan Broder on 12/13/07.
//  Copyright (c) Evan Broder, 2008
//

#import <Kerberos/KLLoginLogoutNotification.h>
#import <Kerberos/CredentialsCache.h>
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
	cc_context_t context = nil;
	cc_ccache_t ccache = nil, defCcache = nil;
	cc_string_t principal = nil, defPrincipal = nil;
	pid_t pid;
	
	// Apparently the OS X ccache API is /retarded/ and requires
	// you to strip the "API:"
	const char * shortCache = strchr(inCredentialsCache, ':');
	if(!shortCache || !(*++shortCache)) return 0;
	
	// Initialize a cc context
	cc_int32 err = cc_initialize(&context, ccapi_version_4, nil, nil);
	
	// Get the principal for the CC that's currently being
	// obtained
	if(err == ccNoError)
		err = cc_context_open_ccache(context, shortCache, &ccache);
	if(err == ccNoError)
		err = cc_ccache_get_principal(ccache, cc_credentials_v5, &principal);
	
	// Get the principal for the default CC
	if(err == ccNoError)
		err = cc_context_open_default_ccache(context, &defCcache);
	if(err == ccNoError)
		err = cc_ccache_get_principal(defCcache, cc_credentials_v5, &defPrincipal);
	
	// If the tickets we're renewing are the same as the default
	// tickets, then run aklog and wait for it to return
	if(!strcmp(defPrincipal->data, principal->data)) {
		if(0 == (pid = fork())) {
			setenv("KRB5CCNAME", inCredentialsCache, TRUE);
			if(execlp("aklog", "aklog", (char *) 0)) {
				perror("aklog");
				exit(1);
			}
		} else {
			waitpid(pid, NULL, 0);
		}
	}
	
	// Cleanup!
	if(defPrincipal != nil)
		cc_string_release(defPrincipal);
	if(defCcache != nil)
		cc_ccache_release(defCcache);
	if(principal != nil)
		cc_string_release(principal);
	if(ccache != nil)
		cc_ccache_release(ccache);
	if(context != nil)
		cc_context_release(context);
    return 0;
}

void KerberosLoginNotification_Logout(
	const char* inCredentialsCache)
{
}
