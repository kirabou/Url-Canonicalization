#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "url.h"

/*
	Run google tests as described in 
	https://developers.google.com/safe-browsing/developers_guide_v3#Canonicalization

	One test is known to fail : "http://3279880203/blah" because canonicalization of IP address 
	is currently not supported.

	To compile : gcc url-test.c url.c -o url-test
*/
	

int main(int argc, char *argv[])
{
	char *str;
	str = url_Canonicalize("http://host/%25%32%35", 0, NULL);
	if(strcmp(str, "http://host/%25")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://host/%25%32%35%25%32%35", 0, NULL);
	if(strcmp(str, "http://host/%25%25")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://host/%2525252525252525", 0, NULL);
	if(strcmp(str, "http://host/%25")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://host/asdf%25%32%35asd", 0, NULL);
	if(strcmp(str, "http://host/asdf%25asd")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://host/%%%25%32%35asd%%", 0, NULL);
	if(strcmp(str, "http://host/%25%25%25asd%25%25")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://www.google.com/", 0, NULL);
	if(strcmp(str, "http://www.google.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/", 0, NULL);
	if(strcmp(str, "http://168.188.99.26/.secure/www.ebay.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/", 0, NULL);
	if(strcmp(str, "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B", 0, NULL);
	if(strcmp(str, "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://3279880203/blah", 0, NULL);
	if(strcmp(str, "http://195.127.0.11/blah")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://www.google.com/blah/..", 0, NULL);
	if(strcmp(str, "http://www.google.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("www.google.com/", 0, NULL);
	if(strcmp(str, "http://www.google.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("www.google.com", 0, NULL);
	if(strcmp(str, "http://www.google.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://www.evil.com/blah#frag", 0, NULL);
	if(strcmp(str, "http://www.evil.com/blah")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://www.GOOgle.com/", 0, NULL);
	if(strcmp(str, "http://www.google.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://www.google.com.../", 0, NULL);
	if(strcmp(str, "http://www.google.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://...www.google.com.../", 0, NULL);
	if(strcmp(str, "http://www.google.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://www.google.com/foo\tbar\rbaz\n2", 0, NULL); 
	if(strcmp(str, "http://www.google.com/foobarbaz2")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://www.google.com/q?", 0, NULL);
	if(strcmp(str, "http://www.google.com/q?")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://www.google.com/q?r?", 0, NULL);
	if(strcmp(str, "http://www.google.com/q?r?")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://www.google.com/q?r?s", 0, NULL);
	if(strcmp(str, "http://www.google.com/q?r?s")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://evil.com/foo#bar#baz", 0, NULL);
	if(strcmp(str, "http://evil.com/foo")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://evil.com/foo;", 0, NULL);
	if(strcmp(str, "http://evil.com/foo;")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://evil.com/foo?bar;", 0, NULL);
	if(strcmp(str, "http://evil.com/foo?bar;")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://\x01\x80.com/", 0, NULL);
	if(strcmp(str, "http://%01%80.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://notrailingslash.com", 0, NULL);
	if(strcmp(str, "http://notrailingslash.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://www.gotaport.com:1234/", 0, NULL);
	if(strcmp(str, "http://www.gotaport.com:1234/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("  http://www.google.com/  ", 0, NULL);
	if(strcmp(str, "http://www.google.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("   www.google.com   ", 0, NULL);
	if(strcmp(str, "http://www.google.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);	
	str = url_Canonicalize("http:// leadingspace.com/", 0, NULL);
	if(strcmp(str, "http://%20leadingspace.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://%20leadingspace.com/", 0, NULL);
	if(strcmp(str, "http://%20leadingspace.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("%20leadingspace.com/", 0, NULL);
	if(strcmp(str, "http://%20leadingspace.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("https://www.securesite.com/", 0, NULL);
	if(strcmp(str, "https://www.securesite.com/")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://host.com/ab%23cd", 0, NULL);
	if(strcmp(str, "http://host.com/ab%23cd")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
	str = url_Canonicalize("http://host.com//twoslashes?more//slashes", 0, NULL);
	if(strcmp(str, "http://host.com/twoslashes?more//slashes")) {
		printf(">>> FAILED [%s]\n", str);
	} else {
		printf("OK: [%s]\n", str);
	}
	free(str);
}