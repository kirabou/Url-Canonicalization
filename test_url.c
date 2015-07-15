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

	To compile : gcc -std=c99 test_url.c url.c -o test_url
*/


void TestCanonicalize(char *url, char *expected_result)
{
	char *str = url_Canonicalize(url, 0, NULL);
	if(str==NULL) {
		fprintf(stderr, "Error while canonicalizing URL\n");
		exit(-1);
	}

	if(strcmp(expected_result, str))
		printf(">>> FAILED [%s]>[%s] expected [%s]>\n", url, str, expected_result);
	else
		printf("PASSED: [%s]>[%s]\n", url, str);

	free(str);


	// Examples of other functions available :

	// char *hostname = url_GetHostname(url);
	// printf("Hostname = [%s]\n", hostname);
	// free(hostname);
	
	// char *test_url = strdup(url);
	// char *query = url_RemoveQuery(test_url, NULL);
	// printf("url=[%s] query=[%s]\n", test_url, query);
	// free(test_url);

	// test_url = strdup(url);
	// char *fragment = url_RemoveFragment(test_url, NULL);
	// if(fragment)
	// 	printf("url=[%s] fragment=[%s]\n", test_url, fragment);
	// free(test_url);
	
	// long length;
	// char *base = url_GetBase(url, 0, &length);
	// printf("Initial url = [%s]\n", url);
	// printf("Base = [%s] (%ld bytes)\n", base, length);
	// free(base);


}




int main(int argc, char *argv[])
{
	TestCanonicalize("http://host/%25%32%35", "http://host/%25");
	TestCanonicalize("http://host/%25%32%35%25%32%35", "http://host/%25%25");
	TestCanonicalize("http://host/%2525252525252525", "http://host/%25");
	TestCanonicalize("http://host/asdf%25%32%35asd", "http://host/asdf%25asd");
	TestCanonicalize("http://host/%%%25%32%35asd%%", "http://host/%25%25%25asd%25%25");
	TestCanonicalize("http://www.google.com/", "http://www.google.com/");
	TestCanonicalize("http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/", "http://168.188.99.26/.secure/www.ebay.com/");
	TestCanonicalize("http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/", "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/");
	TestCanonicalize("http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B", "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+");
	TestCanonicalize("http://3279880203/blah", "http://195.127.0.11/blah");
	TestCanonicalize("http://www.google.com/blah/..", "http://www.google.com/");
	TestCanonicalize("www.google.com/", "http://www.google.com/");
	TestCanonicalize("www.google.com", "http://www.google.com/");
	TestCanonicalize("HTTP://www.evil.com/blah#frag", "http://www.evil.com/blah");
	TestCanonicalize("http://www.GOOgle.com/", "http://www.google.com/");
	TestCanonicalize("http://www.google.com.../", "http://www.google.com/");
	TestCanonicalize("http://www.google.com/foo\tbar\rbaz\n2", "http://www.google.com/foobarbaz2");
	TestCanonicalize("http://www.google.com/q?", "http://www.google.com/q?");
	TestCanonicalize("http://www.google.com/q?r?", "http://www.google.com/q?r?");
	TestCanonicalize("http://www.google.com/q?r?s", "http://www.google.com/q?r?s");
	TestCanonicalize("http://evil.com/foo#bar#baz", "http://evil.com/foo");
	TestCanonicalize("http://evil.com/foo;", "http://evil.com/foo;");
	TestCanonicalize("http://evil.com/foo?bar;", "http://evil.com/foo?bar;");
	TestCanonicalize("http://\x01\x80.com/", "http://%01%80.com/");
	TestCanonicalize("http://notrailingslash.com", "http://notrailingslash.com/");
	TestCanonicalize("http://www.gotaport.com:1234/", "http://www.gotaport.com:1234/");
	TestCanonicalize("  http://www.google.com/  ", "http://www.google.com/");
	TestCanonicalize("http:// leadingspace.com/", "http://%20leadingspace.com/");
	TestCanonicalize("http://%20leadingspace.com/", "http://%20leadingspace.com/");
	TestCanonicalize("%20leadingspace.com/", "http://%20leadingspace.com/");
	TestCanonicalize("https://www.securesite.com/", "https://www.securesite.com/");
	TestCanonicalize("http://host.com/ab%23cd", "http://host.com/ab%23cd");
	TestCanonicalize("http://host.com//twoslashes?more//slashes", "http://host.com/twoslashes?more//slashes");
}
	



