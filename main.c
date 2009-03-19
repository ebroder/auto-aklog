/*
 *  main.c
 *  auto-aklog
 *
 *  Created by Evan Broder on 3/19/09.
 *
 */

#include "afs_princ.h"
#import <Kerberos/CredentialsCache.h>
#include <afs/stds.h>
#include <afs/auth.h>
#include <unistd.h>

int main(int argc, char **argv) {
	char *inCredentialsCache;
	const char *shortCache;
	cc_context_t context = NULL;
	cc_ccache_t ccache = NULL, defCcache = NULL;
	cc_string_t principal = NULL, defPrincipal = NULL;
	int code;
	pid_t pid;
	char *token_princ;
	
	inCredentialsCache = getenv("KRB5CCNAME");
	
	// Apparently the OS X ccache API is /retarded/ and requires
	// you to strip the "API:"
	shortCache = strchr(inCredentialsCache, ':');
	if(!shortCache || !(*++shortCache)) return 0;
	
	// Initialize a cc context
	cc_int32 err = cc_initialize(&context, ccapi_version_4, NULL, NULL);
	
	// Get the principal for the CC that's currently being
	// obtained
	if(err == ccNoError)
		err = cc_context_open_ccache(context, shortCache, &ccache);
	if(err == ccNoError)
		err = cc_ccache_get_principal(ccache, cc_credentials_v5, &principal);
	
	if(err == ccNoError) {
		code = afs_princ(&token_princ);
		if (code == KTC_NOENT)
		{
			// Get the principal for the default CC
			err = cc_context_open_default_ccache(context, &defCcache);
			if(err == ccNoError)
				err = cc_ccache_get_principal(defCcache, cc_credentials_v5, &defPrincipal);
			token_princ = (char *)defPrincipal->data;
		}
	}
	
	if(err == ccNoError) {
		// If the tickets we're renewing are the same as the default
		// tickets, then run aklog and wait for it to return
		if(!strcmp(token_princ, principal->data)) {
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
	}
	
	// Cleanup!
	if (token_princ != NULL && code != KTC_NOENT)
		free(token_princ);
	if(defPrincipal != NULL)
		cc_string_release(defPrincipal);
	if(defCcache != NULL)
		cc_ccache_release(defCcache);
	if(principal != NULL)
		cc_string_release(principal);
	if(ccache != NULL)
		cc_ccache_release(ccache);
	if(context != NULL)
		cc_context_release(context);
	return 0;
}
