/*
	Implements a few useful function to manipulate URLs.
	They have been written to achieved URL canonicalization, as defined in 
	https://developers.google.com/safe-browsing/developers_guide_v3#Canonicalization
 */


#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <ctype.h>
#include <netinet/in.h>

#ifdef __linux__
	#include <bsd/stdlib.h>
#endif

#include "url.h"



// Convert an hexadecimal character [0-9a-zA-Z] to it's integer value
#define VAL(x) ((x>='0' && x<='9') ? x-'0' : ((x>='a' && x<='f') ? x-'a'+10 : ((x>='A' && x<='F') ? x-'A'+10 : 0)))

#define LOWERCASE(x) ((x)>='A' && (x)<='Z' ? (x)-'A'+'a' : (x))

// Convert a "%AB" or "%ab" hexadecimal string to its integer value, or return -1 if was not an hex string
static inline int url_DecodePercent(const char *s) {
	if(	    s
		&&  *s == '%'
	  	&& 	((*(s+1)>='0' &&  *(s+1)<='9') || (*(s+1)>='A' &&  *(s+1)<='F') || (*(s+1)>='a' &&  *(s+1)<='f'))
	  	&& 	((*(s+2)>='0' &&  *(s+2)<='9') || (*(s+2)>='A' &&  *(s+2)<='F') || (*(s+2)>='a' &&  *(s+2)<='f')) )
		return(16*VAL(*(s+1)) + VAL(*(s+2)));	
	else
		return(-1);
}


static char *url_RFC3986_ReservedChars = "!*'();:@&=+$,/?#[]";

/**
 * Check if a given char is one of the RFC 3986 reserved characters,
 * that is one of the following : "!*'();:@&=+$,/?#[]".	
 * @param  c Character to be checked.
 * @return   True if the given character is reserved, false otherwise.
 */
static inline bool url_IsReserved(const char c)
{
	char *ptr = url_RFC3986_ReservedChars;
	while(*ptr)
		if(*ptr==c)
			return(true);
		else 
			ptr++;
	return(false);
}



/**
 * Remove leading and trailing spaces, as well as tab (0x09), CR (0x0d), 
 * and LF (0x0a) characters from the URL. Returns cleaned URL in a newly 
 * allocated string.
 * @param  string  Pointer to string to be cleaned.
 * @param  len     Length of string. If 0, then strlen() will be called.
 * @param  new_len If not NULL, pointer to a size_t where the length of the
 *                 new string will be stored.
 * @return         Pointer to a newly allocated string, must be freed using
 *                 free(), or NULL in case of error.
 */
extern char *url_RemoveTabCRLF(const char *string, size_t len, size_t *new_len)
{
	if(string==NULL)
		return(NULL);

	if(len==0)
		len=strlen(string);

	const char *end_of_string = string + len - 1;

	char *clean = malloc(len + 1);
	if(clean == NULL)
		return(NULL);
	char *begin_clean = clean;

	// Remove leading spaces
	while(*string && *string==' ') 
		string++;

	// Remove trailing spaces
	while(end_of_string-string>=0 && *end_of_string==' ')
		end_of_string--;

	while(end_of_string-string>=0) {
		switch(*string) {
			case '\r':
			case '\n':
			case '\t':
				break;
			default:
				*(clean++) = *string;
				// printf("url_RemoveTabCRLF() char copied = [%c]\n", *string);
				break;
		}
		string++;
	}
	*clean = '\0';

	if(new_len)
		*new_len = clean - begin_clean;

	return(begin_clean);
}


/**
 * Remove the fragment part of an URL. For example, shorten 'http://google.com/#frag' 
 * to 'http://google.com/'. The initial string is changed by putting a NUL character
 * where the first '#' is found.
 * @param  string  Pointer to string holding the fragment.
 * @param  new_len If not NULL, pointer to a size_t where the length of the modified
 *                 string will be stored.
 * @return         Pointer to the fragment string, or NULL.
 */
extern char *url_RemoveFragment(char *string, size_t *new_len)
{
	if(string==NULL)
		return(NULL);

	char *p = string;
	
	for( ; *p && *p!='#'; p++)
		;
	
	if(new_len)
		*new_len = p - string;
	
	if(*p == '#') {
		*p = '\0';
		return(p+1);
	} else 
		return(NULL);
}


/**
 * Remove the query part of an URL (part starting with ?). The initial
 * string is changed by putting a NUL character where the first '?' is found.
 * @param  string  Pointer to a string holding the URL.
 * @param  new_len Pointer to size_t. If not NULL, will be loaded with
 *                 the new length of the shortened URL.
 * @return         Pointer to query part if found, or NULL.
 */
extern char *url_RemoveQuery(char *string, size_t *new_len)
{
	if(string==NULL)
		return(NULL);	

	char *p = string;
	
	for( ; *p && *p!='?'; p++)
		;
	
	if(new_len)
		*new_len = p - string;
	
	if(*p == '?') {
		*p = '\0';
		return(p+1);
	} else 
		return(NULL);
}


/**
 * Percent-decode a string, calling itself until all percent-decoding is done.
 * Returned string is stored in a newly allocated buffer that needs to be freed.
 * @param  string  Pointer to string to be decoded.
 * @param  len     Length of string or 0. If len is 0, strlen() will be called.
 * @param  new_len Pointer to a size_t where to store length of the decoded string.
 *                 Can be NULL if you don't need the length of the returned string.
 * @return         Pointer to a newly allocated decoded string. Needs to be freed
 *                 with free(). NULL if error.
 */
extern inline char *url_Unescape(const char *string, size_t len, size_t *new_len)
{

	if(string==NULL)
		return(NULL);

	if(len==0)
		len=strlen(string);

	char *decoded_string = malloc(strlen(string)+1);
	if(decoded_string==NULL) 
		return(NULL);
	char *begin_decoded = decoded_string;

	for(; *string; string++, decoded_string++) { 
		if(*string == '%') { 
			int code = url_DecodePercent(string);
			if(code != -1) {
				*decoded_string = code; 
				string +=2; 
			} else 
				*decoded_string = *string;
		} else
			*decoded_string = *string; 
	}
	*decoded_string = '\0';	

	size_t decoded_string_length = decoded_string - begin_decoded;
	if(decoded_string_length == len) {
		// No more unescape() needed
		if(new_len)
			*new_len = decoded_string - begin_decoded;
		return(begin_decoded);
	} else {
		// Recursevely call Unescape()
		char *next_string = url_Unescape(begin_decoded, decoded_string_length, new_len);
		free(begin_decoded);
		return(next_string);
	}

}



/**
 * Normalize an URL. The URL will be cleaned with url_RemoveTabCRLF(), then its 
 * fragment will be removed with url_RemoveFragment(). The URL will be unescaped
 * with url_Unescape() before being normalizes. Return a normalized URL in a 
 * newly allocated block of memory or NULL if error. 
 * @param  src     Pointer to string holding the URL to be normalized.
 * @param  len     Length of source string. If 0, strlen() will be called.
 * @param  new_len If not NULL, pointer to a size_t where the length of the new string will be stored.
 * @return         Pointer to a newly allocated string. Must freed using free(). Or
 *                 NULL of error.
 */
extern char *url_Normalize(const char *src, const size_t len, size_t *new_len)
{
	if(src==NULL)
		return(NULL);

	size_t tmp;

	if(new_len == NULL)
		new_len = &tmp;

// printf("url_Normalize() [%s]\n", src);

	char *str1 = url_RemoveTabCRLF(src, len, new_len);
	if(str1==NULL)
		return(NULL);
	if(strlen(str1) == 0) {
		free(str1);
		return(NULL);
	}
// printf("%-16s = [%s]\n", "CLEANED", str1);
// printf("new_len = %ld\n", *new_len);
	url_RemoveFragment(str1, new_len);
// printf("%-16s = [%s]\n", "FRAGMENT REMOVED", str1);
// printf("new_len = %ld\n", *new_len);	
	char *str2 = url_Unescape(str1, *new_len, new_len);
	if(str2==NULL) {
		free(str1);
		return(NULL);
	}
// printf("%-16s = [%s]\n", "UNESCAPED", str2);
// printf("new_len = %ld\n", *new_len);		

	// Save begining of source string
	char *begin_source = str2;

	// Destination string cannot be longer that the initial string + "http://" + trailing '/'
	// Add 15 bytes in case the hostname is an int to be converted in an IPv4 address
	char *dest = malloc(*new_len+1+8+12+15);
	if(dest==NULL)
		return(NULL);

	// Save the beginning of the destination string
	char *begin_dest = dest;

	// Look for end of scheme
	char *end_of_scheme = begin_source;
	for( ; *end_of_scheme!='\0' && *end_of_scheme!=':'; end_of_scheme++)
		;
	if(*end_of_scheme==':' && *(end_of_scheme+1)=='/' && *(end_of_scheme+2)=='/') {
		// Copy the scheme part
		for( ; *str2 && *str2!=':'; dest++, str2++)
			*dest = LOWERCASE(*str2);
		if( *(str2)==':' && *(str2+1)=='/' && *(str2+2)=='/') {
			// Copy the "://" part
			*(dest++) = *(str2++); *(dest++) = *(str2++); *(dest++) = *(str2++);
		} else {
			goto bad;
		}
	} else { 
		// No scheme part, use "http" as default
		str2 = begin_source;
		dest = begin_dest;
		strcpy(dest, "http://");
		dest +=7;	
	}

	// Skip leading '/' if any
	for( ; *str2=='/'; str2++)
		;

	// Find end of the host name
	char *begin_hostname = str2;
	while(*str2 && *str2!='/' && *str2!='?')
		str2++;
	char *end_hostname = str2-1;

	// Ignore leading dots
	while(*begin_hostname && *begin_hostname=='.')
		begin_hostname++;

	// Ignore trailing dots
	while(end_hostname-begin_hostname>0 && *end_hostname=='.')
		end_hostname--;

	// Check if hostname is only made of digits
	char *s1 = begin_hostname, *s2 = end_hostname;
	bool hostname_is_number = true;
	for( ; s2-s1>=0; s1++) {
		if( *s1 < '0' || *s1 > '9' ) {
			hostname_is_number = false;
			break;
		}
	}

	if(hostname_is_number) {
		// If hostname is only made of digits, convert to an IP address
		unsigned long ip_addr = htonl(strtoul(begin_hostname, NULL, 10));
		unsigned char *p = (unsigned char *)(&ip_addr);
		dest += sprintf(dest, "%u.%u.%u.%u", *p, *(p+1), *(p+2), *(p+3));
	} else {
		// Else copy the host name, making sure all characters are lowercase
		for( ; end_hostname-begin_hostname>=0; dest++, begin_hostname++)
			*dest = LOWERCASE(*begin_hostname);
	}

	// str2++;
	if(*(dest-1)!='/')
		*(dest++)='/';

	// if(*str2!='/') { 
	// 	*dest = '\0';
	// 	goto good;
	// }

	char *after_hostname = dest;

	bool in_query = false;
	while(*str2) {
		if(in_query) {
			// If in query, just copy the character
			*(dest++) = *(str2++);
		} else {
			// We are in the path
			switch(*str2) {
				case '?':
					// Entering query
					*(dest++) = *(str2++);
					in_query = true;
					break;
				case '/':
					if(*(str2+1)=='.' && *(str2+2)=='/') {
						// replace "/./" with "/"
						*(dest++) = '/';
						str2 +=2;
					} else if(*(str2+1)=='.' && *(str2+2)=='.' && (*(str2+3)=='/' || *(str2+3)=='\0')) {
						// Remove "/../" along with the preceding path component.
						if(*(str2+3)=='\0')
							str2 +=3;
						else str2 +=3;
						if(*(dest-1)=='/')
							dest--;
						do {
							dest--;
						} while(dest-after_hostname>=0 && *dest!='/');
						dest++;
					} else
						*(dest++) = *(str2++);
					// Replace runs of consecutive slashes with a single slash character.
					if(*(dest-1)=='/' && *(dest-2)=='/')
						dest--;
					break;
				default:
					*(dest++) = *(str2++);
			}
		}
// printf("%.*s\n", (int)(dest-begin_dest), begin_dest);
	}
	*dest='\0';

// good:
	free(str1); free(begin_source);
	if(new_len)
		*new_len = dest - begin_dest;
// printf("url_Normalize() END dest=[%s] len=%ld\n", begin_dest, dest-begin_dest);
	return(begin_dest);

bad:
// printf("This is bad\n");
	free(str1); 
	free(begin_source);
	if(begin_dest) {
		free(begin_dest);
	}
	return(NULL);
}


/**
 * Percent-encode a string to be used as an URL. Return the encoded URL in a
 * newly allocated buffer of NULL if error. Reserved characters are not
 * encoded.
 * @param  src     Pointer to source string to be percent-encoded.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a size_t where the length of the new string will be stored.
 * @return         Pointer to newly allocated string. Must be freed with free().
 *                 Or NULL if error.
 */
extern char *url_Escape(const char *src, size_t len, size_t *new_len)
{
	if(src==NULL)
		return(NULL);

	const unsigned char *usrc = (unsigned char *)src;
	if(len==0)
		len = strlen(src);

	char *dest = malloc(3*len+1);
	if(dest==NULL)
		return(NULL);
	char *begin_dest = dest;

	while(*usrc) {
		if(*usrc<=32 || *usrc>=127 || *usrc=='#' || *usrc=='%') {
			sprintf(dest, "%%%02X", *(usrc++));
			dest +=3;
		} else {
			*(dest++) = *(usrc++);
		}
	}

	*dest='\0';

	if(new_len)
		*new_len = dest - begin_dest;
	return(begin_dest);	
}


/**
 * Percent-encode a string to be used as an URL, including all the reserved
 * characters defined in url_RFC3986_ReservedChars, while url_Escape() 
 * does not encode reserved characters). Return the encoded URL in a
 * newly allocated buffer of NULL if error. 
 * @param  src     Pointer to source string to be percent-encoded.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a size_t where the length of the new string will be stored.
 * @return         Pointer to newly allocated string. Must be freed with free().
 *                 Or NULL if error.
 */
extern char *url_EscapeIncludingReservedChars(const char *src, size_t len, size_t *new_len)
{
	if(src==NULL)
		return(NULL);

	const unsigned char *usrc = (unsigned char *)src;
	if(len==0)
		len = strlen(src);

	char *dest = malloc(3*len+1);
	if(dest==NULL)
		return(NULL);
	char *begin_dest = dest;

	while(*usrc) {
		if(*usrc<=32 || *usrc>=127 || *usrc=='%' || url_IsReserved((char)*usrc)) {
			sprintf(dest, "%%%02X", *(usrc++));
			dest +=3;
		} else {
			*(dest++) = *(usrc++);
		}
	}

	*dest='\0';

	if(new_len)
		*new_len = dest - begin_dest;
	return(begin_dest);	
}



/**
 * Canonicalize an URL as described in 
 * https://developers.google.com/safe-browsing/developers_guide_v3#Canonicalization.
 * Reserved characters "!*'();:@&=+$,/?#[]" are not encoded.
 * Return canonicalized URL is a newly allocated buffer, or NULL if error.
 * @param  src     Pointer to source string holding the URL to be canonicalized.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a size_t where the length of the new string will be stored.
 * @return         Pointer to newly allocated string holding the canonicalized URL,
 *                 or NULL if error. Must be freed with free().
 */
extern char *url_Canonicalize(const char *src, size_t len, size_t *new_len)
{
	if(src==NULL)
		return(NULL);

	size_t tmp;
	if(new_len == NULL)
		new_len = &tmp;
	
	char *str3 = url_Normalize(src, len, new_len);
	if(str3==NULL)
		return(NULL);
	char *str4 = url_Escape(str3, *new_len, new_len);

	free(str3);
	return(str4);
}


/**
 * Canonicalize an URL as described in 
 * https://developers.google.com/safe-browsing/developers_guide_v3#Canonicalization.
 * Reserved characters "!*'();:@&=+$,/?#[]" ARE encoded.
 * Return canonicalized URL is a newly allocated buffer, or NULL if error.
 * @param  src     Pointer to source string holding the URL to be canonicalized.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a size_t where the length of the new string will be stored.
 * @return         Pointer to newly allocated string holding the canonicalized URL,
 *                 or NULL if error. Must be freed with free().
 */
extern char *url_CanonicalizeWithFullEscape(const char *src, size_t len, size_t *new_len)
{
	if(src==NULL)
		return(NULL);

	size_t tmp;
	if(new_len == NULL)
		new_len = &tmp;

	char *str3 = url_Normalize(src, len, new_len);
	if(str3==NULL)
		return(NULL);
	char *str4 = url_EscapeIncludingReservedChars(str3, *new_len, new_len);

	free(str3);
	return(str4);
}



/**
 * Encode a string to be compliant with application/x-www-form-urlencoded format.
 * It is the same as url_EscapeIncludingReservedChars() but it also replaces 
 * spaces with '+'. (NOTE & WARNING: THIS CODE IS OBVIOUSLY WRONG AS 32 AND ' '
 * ARE ACTUALLY THE SAME SPACE CHARACTER !!)
 * @param  src     Pointer to string to be encoded.
 * @param  len     Length of string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a size_t where the length of the 
 *                 encoded string will be stored.
 * @return         Pointer to newly allocated string holding 
 *                 or NULL if error. Must be freed with free().
 */
extern char *url_Encode(const char *src, size_t len, size_t *new_len)
{
	if(src==NULL)
		return(NULL);

	if(len==0)
		len = strlen(src);

	size_t length;

	// make sure URL is clean
	char *str = url_Unescape(src, len, &length);
	if(str==NULL)
		return(NULL);

	char *dest = malloc(3*length+1);
	if(dest==NULL) {
		free(str);
		return(NULL);
	}
	char *begin_dest = dest;

	unsigned char *usrc = (unsigned char *)str;
	while(*usrc) {
		if(*usrc<=32 || *usrc>=127 || *usrc=='%' || url_IsReserved((char)*usrc)) {
			sprintf(dest, "%%%02X", *(usrc++));
			dest +=3;
		} else if(*usrc==' ') {
			// (NOTE & WARNING: THIS CODE IS OBVIOUSLY WRONG AS 32 AND ' '
 			// ARE ACTUALLY THE SAME SPACE CHARACTER !!
			*(dest++) = '+';
			usrc++;
		} else {
			*(dest++) = *(usrc++);
		}
	}

	*dest='\0';

	free(str);

	if(new_len)
		*new_len = dest - begin_dest;
	return(begin_dest);	
}


inline static bool url_IsSeparator(char c, const char *separators_list)
{
	const char *separators = separators_list ? separators_list : "&;";
	for(; *separators; separators++) {
		if(*separators == c)
			return(true);
	}
	return(false);
}

/**
 * Parse a "key=value&key=value&key=value" string. You can use the default separator
 * characters (';' and '&') or provide your own list of separator characters. 
 * Note that the original string is modified : '=', and separator characters 
 * are replaced by the NUL character. Each call return to next key-value
 * pair, as well as a pointer to where the next parsing has to be made. If the value part
 * was between double-quotes, those will be removed. If one part of the pair is missing,
 * the value found will be returned as key. For example, when calling this function
 * with the string "0;URL=http://verifrom.com", the first call will returned "0" as key,
 * and NULL as value. The second call will return "URL" as key and "http://verifrom.com"
 * as value.
 * @param  string          String to be parsed.
 * @param  key_string      Pointer to a string pointer. Will be loaded with a pointer to
 *                         the beginning of the key-string in the initial string. Will be
 *                         NULL if no value found.
 * @param  value_string    Pointer to a string pointer. Will be loaded with a pointer to
 *                         the beginning of the key-value in the initial string. Will be
 *                         NULL if no value found.
 * @param  separators_list String made of the separator characters you want to use, or NULL.
 	                       If NULL, the dfault list ";&" is used.
 * @return                 Pointer to the remainder of the initial string to be parsed,
 *                         or NULL if there is nothing left to be parsed.
 */
extern char *url_ParseNextKeyValuePair(char *string, char **key_string, char **value_string, const char *separators_list)
{
    if(string==NULL || key_string==NULL || value_string==NULL)
        return(NULL);

    if(separators_list==NULL)
    	separators_list = "&;";
 
    // for now, we found nothing
    *key_string = NULL;
    *value_string = NULL;

    // our index to parse string
    int ix=0;

    // strip leading blanks 
    while(string[ix]!=0 && !(isalnum(string[ix])))
        ix++;

    // we just found the start of the key_string
    (*key_string) = (string + ix);

    // if we reached the end of string, we must stop here
    if(string[ix]==0) 
        return(NULL);

    // accept all characters up to blanks or = or NUL or & OR ;
    ix++;
    // while(string[ix]!=0 && (isalnum(string[ix])||string[ix]=='-'||string[ix]=='_') && string[ix]!=';' && string[ix]!='&')
    while(string[ix]!=0 && (isalnum(string[ix])||string[ix]=='-'||string[ix]=='_') && !url_IsSeparator(string[ix], separators_list))
        ix++;   

    // if we reached the end of string, we must stop here
    if(string[ix]==0) return(NULL);

    // remember the position so we can come back to put a NUL char here
    char *end_of_key_string = string+ix;

    // Look for a =
    // while(string[ix]!=0 && string[ix]!='=' && string[ix]!='&' && string[ix]!=';')
    while(string[ix]!=0 && string[ix]!='=' && !url_IsSeparator(string[ix], separators_list))
        ix++;

    if(string[ix]==0) 
        return(NULL);

    // if(string[ix]=='&' || string[ix]==';') {
    if(url_IsSeparator(string[ix], separators_list)) {
    	(*end_of_key_string) = 0;
    	return(string[ix+1] ? string+ix+1 : NULL);
    }

    (*end_of_key_string) = 0;

    // Now we need to find the beginning of our value_string
    ix++;

    // Strip blanks
    while(string[ix]!=0 && string[ix]<=0x20)
        ix++;       

    if(string[ix]==0) return(NULL);

    // This is a special case if key=="URL". In that case,
    // we will read up to the end of string to load the value
    if(strcasecmp(*key_string, "url") == 0)
    	separators_list = "";

    bool quoted_string = (string[ix]=='"' || string[ix]=='\'');
    char quote_char = quoted_string ? string[ix] : '\0';

    if(quoted_string) {
        ix++;
        (*value_string) = string+ix;
        while(string[ix]!=0 && string[ix]!=quote_char)
            ix++;
    } else {
        (*value_string) = string+ix;
        ix++;
        // while(string[ix]!=0 && string[ix]!=';')
        while(string[ix]!=0 && !url_IsSeparator(string[ix], separators_list))
            ix++;
    }

    if(string[ix]==0) return(NULL);

    // Mark end of value string
    string[ix]=0;

    return(string[ix+1] ? string+ix+1 : NULL);
}


/**
 * Split an URL into scheme, link, and query parts, as defined by RFC3986.
 * Warning : the original URL is modified (NUL characters are inserted to split
 * the original string in parts). Make sure the URL has been normalized before
 * calling this function.
 * @param url      URL to be split.
 * @param scheme   If not null, must be a pointer to a char*. Will be set to the beginning
 *                 of the scheme part in URL.
 * @param link     If not null, must be a pointer to a char*. Will be set to the beginning
 *                 of the link part in URL, or NULL or empty if none found.
 * @param query    If not null, must be a pointer to a char*. Will be set to the beginning
 *                 of the query part in URL, or NULL or empty if none found.
 */
extern void url_Split(char *url, char **scheme, char **link, char **query)
{
	if(url==NULL)
		return;

	char *found_scheme=NULL, *found_link=NULL, *found_query=NULL;
	int pos=0;
	enum { BEGIN, AFTER_SCHEME, AFTER_LINK, AFTER_QUERY } state=BEGIN;

	while(url[pos]) {
		switch(url[pos]) {
			case ':':
				if(state==BEGIN) {
					found_scheme=url;
					state=AFTER_SCHEME;
					url[pos]='\0';
					found_link = url+pos+1;
				}
				break;
			case '?' :
				if(state==BEGIN || state==AFTER_SCHEME) {
					state=AFTER_LINK;
					url[pos]='\0';
					found_query = url+pos+1;							
				}
				break;
			// case '#' :
			// 	if(state==BEGIN || state==AFTER_SCHEME || state==AFTER_LINK) {
			// 		state=AFTER_QUERY;
			// 		url[pos]='\0';
			// 		found_fragment = url+pos+1;							
			// 	}
			// 	break;			
		}
		pos++;
	}

	if(found_link==NULL && found_scheme==NULL)
		found_link=url;

	if(scheme)   *scheme   = found_scheme;
	if(link)     *link     = found_link;
	if(query)    *query    = found_query;
	// if(fragment) *fragment = found_fragment;

	// if(found_scheme)   printf("url_Split() scheme=[%s]\n", found_scheme);
	// if(found_link)     printf("url_Split() link=[%s]\n", found_link);
	// if(found_query)    printf("url_Split() query=[%s]\n", found_query);
	// if(found_fragment) printf("url_Split() fragment=[%s]\n", found_fragment);

}


/**
 * Return the hostname part extracted from an url in a newly allocated string.
 * @param  url     Pointer to an URL.
 * @return         Pointer to a newly allocated string holding the hostname
 *                 extracted from the URL. Use free() to deallocate the memory.
 */
extern char *url_GetHostname(const char *url)
{
	// Make sure we have an url
	if(url==NULL)
		return(NULL);

	// Make sure we have a normalized url
	char *clean = url_Normalize(url, 0, NULL);
	if(clean==NULL)
		return(NULL);

	// Find the link part of the url
	char *link;
	url_Split(clean, NULL, &link, NULL);

	if(link==NULL) {
		fprintf(stderr, "url_GetHostname() cannot find link part in URL [%s]\n", url);
		free(clean);
		return(NULL);
	}

	// Skip leading '//'
	link +=2;

	// Skip leading "www." if any
	if(link[0]=='w' && link[1]=='w' && link[2]=='w' && link[3]=='.')
		link +=4;

	// Find the end of the hostname in link, that
	// is the first '/' or ':' we meet.
 	for(char *p=link; *p; p++)
		if(*p=='/' || *p==':') {
			*p = '\0';
			break;
		}

	// Make a copy of the hostname
	char *hostname = url_Encode(link, 0, NULL);

	// Free the cleaned url we created
	free(clean);

	// Return hostname
	return(hostname);

}




/**
 * Return the hostname part extracted from an url in a newly allocated string,
 * without skiping the www. header.
 * @param  url     Pointer to an URL.
 * @return         Pointer to a newly allocated string holding the hostname
 *                 extracted from the URL. Use free() to deallocate the memory.
 */
extern char *url_GetHostnameWWW(const char *url)
{
	// Make sure we have an url
	if(url==NULL)
		return(NULL);

	// Make sure we have a normalized url
	char *clean = url_Normalize(url, 0, NULL);
	if(clean==NULL)
		return(NULL);

	// Find the link part of the url
	char *link;
	url_Split(clean, NULL, &link, NULL);

	if(link==NULL) {
		fprintf(stderr, "url_GetHostname() cannot find link part in URL [%s]\n", url);
		free(clean);
		return(NULL);
	}

	// Skip leading '//'
	link +=2;

	// Skip leading "www." if any
	// if(link[0]=='w' && link[1]=='w' && link[2]=='w' && link[3]=='.')
	// 	link +=4;

	// Find the end of the hostname in link, that
	// is the first '/' or ':' we meet.
 	for(char *p=link; *p; p++)
		if(*p=='/' || *p==':') {
			*p = '\0';
			break;
		}

	// Make a copy of the hostname
	char *hostname = url_Encode(link, 0, NULL);

	// Free the cleaned url we created
	free(clean);

	// Return hostname
	return(hostname);

}



/**
 * Return the base part of an URL in a newly allocated string.
 * @param  url     Pointer to string holding the URL.
 * @param  len     Length of URL, strlen() will be used if 0.
 * @param  new_len If not NULL, pointer to a size_t where the length of the new
 *                 string will be stored.
 * @return         Pointer to a newly allocated string holding the
 *                 base part of the initial URL.
 */
extern char *url_GetBase(const char *url, size_t len, size_t *new_len)
{
	if(url==NULL)
		return(NULL);

	if(len == 0)
		len = strlen(url);

	size_t tmp=0;
	if(new_len == NULL)
		new_len = &tmp;

	char *str = url_Normalize(url, len, NULL);
	if(str==NULL)
		return(NULL);
	url_RemoveQuery(str, new_len);

	// Remove the last part of the URL until we found a '/'
	char *end = str + *new_len - 1;
	for( ; end-str>=0 && *end!='/'; end--)
		;
	*(++end) = '\0';

	*new_len = end - str;

	return(str);
}


/**
 * Return the scheme part of an URL in a newly allocated string
 * @param  url Pointer to string holding the URL.
 * @return     Pointer to a newly allocated string holding the
 *             scheme part of the initial URL.
 */
extern char *url_GetScheme(const char *url)
{
	if(url==NULL)
		return(NULL);

	char *ptr = strstr(url, "://");
	if(ptr==NULL)
		return(NULL); 
	size_t scheme_length = ptr - url + 3;
	char *scheme = malloc(scheme_length + 1);
	if(scheme) {
		memcpy(scheme, url, scheme_length);
		scheme[scheme_length] = '\0';
	}
	return(scheme);
}



/**
 * Test if a given URL is absolute (ie. starting with http:// or https://).
 * @param  url URL to be tested.
 * @return     true if the URL is absolute, or false.
 */
extern bool url_IsAbsolute(const char *url)
{
	if(url==NULL)
		return(false);

	return(
		strncasecmp(url, "http://", 7)==0 || strncasecmp(url, "https://", 8)==0
		? true
		: false
	);
}


/**
 * Make an absolute URL in a newly allocated memory string. If the given
 * URL is already absolute, a simple copy is made.
 * @param  parent_url Parent URL from which the "absolute" part will be
 *                    extracted. Must be absolute, obviously. Must be
 *                    unescaped.
 * @param  url        Absolute or relative URL from which an absolute one
 *                    must be built. The "absolute" is built based on the
 *                    given parent_url. Must be unescaped.
 * @return            Newly allocated string holding the absolute url for
 *                    the given URL, or NULL if error.
 */
extern char *url_MakeAbsolute(const char *parent_url, const char *url)
{
	// Check arguments
	if(parent_url==NULL || url==NULL)
		return(NULL);

	// Save fragment if any
	char *fragment = url_GetFragment(url);

	size_t normalized_url_len = 0;
	char *normalized_url = NULL;

	if(url_IsAbsolute(url)) {

		// Case where the relative URL is actually an absolute URL.
		// Normalize to manage possible /./, // or /../ in path.
		normalized_url = url_Normalize(url, strlen(url), &normalized_url_len);

	} else {

		// Build absolute URL without fragment
		size_t base_url_len=0;
		char *base_url = url_GetBase(parent_url, 0, &base_url_len);
		char *absolute_url = malloc(base_url_len + strlen(url) + 1);
		if(url[0]=='/' && url[1]=='/') {
			char *scheme = url_GetScheme(parent_url);
			sprintf(absolute_url, "%s%s", scheme?scheme:"", url+2);
			free(scheme);
		} else if(url[0]=='/') {
			char *scheme = url_GetScheme(parent_url);
			char *hostname = url_GetHostnameWWW(parent_url);
			sprintf(absolute_url, "%s%s%s", scheme?scheme:"", hostname?hostname:"", url);
			free(scheme);
			free(hostname);
		} else
			sprintf(absolute_url, "%s%s", base_url, url);
		free(base_url);

		// Normalize to manage possible /./, // or /../ in path.
		normalized_url = url_Normalize(absolute_url, strlen(absolute_url), &normalized_url_len);
		free(absolute_url);

	}

	// Restore saved fragment
	if(fragment) {
		char *absolute_url = malloc(normalized_url_len + strlen(fragment) + 2);
		sprintf(absolute_url, "%s#%s", normalized_url, fragment);
		free(fragment);
		free(normalized_url);
		return(absolute_url);
	} else {
		return(normalized_url);
	}
	
}



/**
 * Skip the scheme part of an URL. Return pointer to first
 * character in the URL after the scheme part, or pointer to
 * first character in URL if no scheme found.
 * @param  url Pointer to string holding the URL.
 * @return     Pointer to first character in the URL after the
 *             scheme part, or pointer to first character in 
 *             URL if no scheme part found.
 */
extern const char *url_SkipScheme(const char *url)
{
	if(url==NULL)
		return(NULL);	
	char *p = strstr(url, "://");
	return( p ? p+3 : url);
}


/**
 * Skip the wwww. part of a scheme less URL.
 * @param  url_schemeless Pointer to a scheme less URL
 * @return                Pointer into url_schemless where
 *                        the "www." part ends.
 */
extern const char *url_SkipWWW(const char *url_schemeless)
{
	if(url_schemeless==NULL)
		return(NULL);
	if(url_schemeless[0]=='w' && url_schemeless[1]=='w' && url_schemeless[2]=='w' && url_schemeless[3]=='.')
		return(url_schemeless+4);
	else
		return(url_schemeless);
}



/**
 * Get fragment of an unescaped URL in a newly allocated string.
 * @param  url Pointer to unescaped URL.
 * @return     Pointer to fragment part of the URL in a newly allocated
 *             buffer, or NULL if none found. The returned buffer
 *             must be free()
 */
extern char *url_GetFragment(const char *url)
{
	if(url==NULL)
		return(NULL);
	for( ; *url && *url!='#'; url++)
		;
	if(*url == '#')
		return(strdup(url+1));
	else
		return(NULL);
}




