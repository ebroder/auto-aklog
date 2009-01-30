/*
 *  k4name_parse.c
 *  auto-aklog
 *
 *  Created by Evan Broder on 1/30/09.
 *
 */

#include <kerberosIV/krb.h>
#include <string.h>
#include "k4name_parse.h"

#define FULL_SZ (ANAME_SZ + INST_SZ + REALM_SZ)

#define NAME    0               /* which field are we in? */
#define INST    1
#define REALM   2

int
k4name_parse(char *np, char *ip, char *rp, char *fullname)
{
	char buf[FULL_SZ];
	char *rnext, *wnext;        /* next char to read, write */
	register char c;
	int backslash;
	int field;
	
	backslash = 0;
	rnext = buf;
	wnext = np;
	field = NAME;
	
	if (strlen(fullname) > FULL_SZ)
		return KNAME_FMT;
	(void) strcpy(buf, fullname);
	
	while ((c = *rnext++)) {
		if (backslash) {
			*wnext++ = c;
			backslash = 0;
			continue;
		}
		switch (c) {
			case '\\':
				backslash++;
				break;
			case '.':
				switch (field) {
					case NAME:
						if (wnext == np)
							return KNAME_FMT;
						*wnext = '\0';
						field = INST;
						wnext = ip;
						break;
					case INST:          /* We now allow period in instance */
					case REALM:
						*wnext++ = c;
						break;
					default:
						DEB (("unknown field value\n"));
						return KNAME_FMT;
				}
				break;
			case '@':
				switch (field) {
					case NAME:
						if (wnext == np)
							return KNAME_FMT;
						*ip = '\0';
						/* fall through */
					case INST:
						*wnext = '\0';
						field = REALM;
						wnext = rp;
						break;
					case REALM:
						return KNAME_FMT;
					default:
						DEB (("unknown field value\n"));
						return KNAME_FMT;
				}
				break;
			default:
				*wnext++ = c;
		}
		/*
		 * Paranoia: check length each time through to ensure that we
		 * don't overwrite things.
		 */
		switch (field) {
			case NAME:
				if (wnext - np >= ANAME_SZ)
					return KNAME_FMT;
				break;
			case INST:
				if (wnext - ip >= INST_SZ)
					return KNAME_FMT;
				break;
			case REALM:
				if (wnext - rp >= REALM_SZ)
					return KNAME_FMT;
				break;
			default:
				DEB (("unknown field value\n"));
				return KNAME_FMT;
		}
	}
	*wnext = '\0';
	return KSUCCESS;
}
