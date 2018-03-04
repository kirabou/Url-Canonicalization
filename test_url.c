#define _BSD_SOURCE

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

	To compile : gcc -std=c99 -Wall test_url.c url.c -o test_url
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

}


void TestMakeAbsolute(char *parent_url, char *url, char *expected_result)
{
	char *absolute_url = url_MakeAbsolute(parent_url, url);
	if(absolute_url==NULL) {
		fprintf(stderr, "Error while making absolute URL\n");
		exit(-1);
	}

	if(strcmp(expected_result, absolute_url))
		printf(">>> FAILED [%s], [%s] >[%s] expected [%s]>\n", parent_url, url, absolute_url, expected_result);
	else
		printf("PASSED: [%s], [%s] >[%s]\n", parent_url, url, absolute_url);

	free(absolute_url);
}




int main(int argc, char *argv[])
{
	char *url = "http://www.may.in/wp/le-groupe2.html/access-adress.php?bill=1274f42adc7%2Fpart%2Fabo2F&value2=put some value here; value3#fragment";

	char *url_canonicalized = url_Canonicalize(url, 0, NULL);
	printf ("  url_canonicalized = [%s]\n", url_canonicalized);
	free(url_canonicalized);

	char *hostname = url_GetHostname(url);
	printf("  Hostname = [%s]\n", hostname);
	free(hostname);
	
	char *test_url = strdup(url);
	char *query = url_RemoveQuery(test_url, NULL);
	printf("  url without query = [%s]\n  query = [%s]\n", test_url, query);
	free(test_url);

	test_url = strdup(url);
	char *fragment = url_RemoveFragment(test_url, NULL);
	if(fragment)
		printf("  url without fragment =[%s]\n  fragment=[%s]\n", test_url, fragment);
	free(test_url);
	
	size_t length;
	char *base = url_GetBase(url, 0, &length);
	printf("  base = [%s] (%ld bytes)\n", base, length);
	free(base);

	char *url_normalized = url_Normalize(url, 0, NULL);
	printf("  url_normalized = [%s]\n", url_normalized);
	free(url_normalized);

	char *url_to_split = url_Normalize(url, 0, NULL);
	char *scheme, *link;
	url_Split(url_to_split, &scheme, &link, &query);
	printf("  scheme = [%s]\n  link = [%s]\n  query = [%s]\n",
		scheme, link, query);
	char *key, *value ;
	while(query) {
		query = url_ParseNextKeyValuePair(query, &key, &value, NULL);
		printf("    key=[%s] value=[%s] remainder=[%s]\n", key, value, query);		
	}
	free(url_to_split);


	TestCanonicalize("  123example.com:80", "http://123example.com:80/");
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

	TestMakeAbsolute("http://WebReference.com/html/", "about.html?test#truc", "http://webreference.com/html/about.html?test#truc");
	TestMakeAbsolute("http://WebReference.com/html/", "tutorial1/", "http://webreference.com/html/tutorial1/");
	TestMakeAbsolute("http://WebReference.com/html/", "tutorial1/2.html", "http://webreference.com/html/tutorial1/2.html");
	TestMakeAbsolute("http://www.WebReference.com/html/", "/", "http://www.webreference.com/");
	TestMakeAbsolute("http://www.WebReference.com/html/", "/tutorial1/2.html", "http://www.webreference.com/tutorial1/2.html");
	TestMakeAbsolute("http://WebReference.com/html/", "//www.internet.com/", "http://www.internet.com/");
	TestMakeAbsolute("http://WebReference.com/html/", "/experts/", "http://webreference.com/experts/");
	TestMakeAbsolute("http://WebReference.com/html/", "../", "http://webreference.com/");
	TestMakeAbsolute("http://WebReference.com/html/", "../experts/", "http://webreference.com/experts/");
	TestMakeAbsolute("http://WebReference.com/html/", "../../../", "http://webreference.com/");
	TestMakeAbsolute("http://WebReference.com/html/", "./", "http://webreference.com/html/");
	TestMakeAbsolute("http://WebReference.com/html/", "./about.html?test#truc", "http://webreference.com/html/about.html?test#truc");
	TestMakeAbsolute("http://WebReference.com/html/", "./abouT.html?teSt#Truc", "http://webreference.com/html/abouT.html?teSt#Truc");

	TestMakeAbsolute("http://www.bucknell.edu/home/dir/level3/file.html", "http://www.bucknell.edu/home/dir/level3/file.html", "http://www.bucknell.edu/home/dir/level3/file.html");
	TestMakeAbsolute("http://www.bucknell.edu/home/dir/level3/file.html", "http://cnn.com:90//testpages/grading.html", "http://cnn.com:90/testpages/grading.html");
	TestMakeAbsolute("http://www.bucknell.edu/home/dir/level3/file.html", "http://cnn.com:80//testpages/grading.html", "http://cnn.com:80/testpages/grading.html");
	TestMakeAbsolute("http://www.bucknell.edu/home/dir/level3/file.html", "http://cnn.com/level0/././testpages/../level1/lelve2/../../grading.html#abc", "http://cnn.com/level0/grading.html#abc");
	TestMakeAbsolute("http://www.bucknell.edu/home/dir/level3/file.html", "../testpages/level2/../level3/grading.html", "http://www.bucknell.edu/home/dir/testpages/level3/grading.html");
	TestMakeAbsolute("http://www.bucknell.edu/home/dir/level3/file.html", "../testpages/level2/../level3/.././grading.html#abc", "http://www.bucknell.edu/home/dir/testpages/grading.html#abc");
	TestMakeAbsolute("http://www.bucknell.edu/home/dir/level3/file.html", "../grading.html#abc", "http://www.bucknell.edu/home/dir/grading.html#abc");
	TestMakeAbsolute("http://www.bucknell.edu/home/dir/level3/file.html", "../grading.html#", "http://www.bucknell.edu/home/dir/grading.html#");
	TestMakeAbsolute("http://www.bucknell.edu/home/dir/level3/file.html", "grading.html#abc", "http://www.bucknell.edu/home/dir/level3/grading.html#abc");
	TestMakeAbsolute("http://www.bucknell.edu/home/dir/level3/file.html", "/grading.html#abc", "http://www.bucknell.edu/grading.html#abc");
	TestMakeAbsolute("http://www.bucknell.edu/home/dir/level3/file.html", "../testpages/level1/level2/../level3/grading.html", "http://www.bucknell.edu/home/dir/testpages/level1/level3/grading.html");



}
	



