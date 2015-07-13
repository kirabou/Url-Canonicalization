/*
	Implements a few useful function to manipulate URLs.
	They have been written to achieved URL canonicalization, as defined in 
	https://developers.google.com/safe-browsing/developers_guide_v3#Canonicalization
 */



#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>


// Convert an hexadecimal character [0-9a-zA-Z] to it's integer value
#define VAL(x) ((x>='0' && x<='9') ? x-'0' : ((x>='a' && x<='f') ? x-'a'+10 : ((x>='A' && x<='F') ? x-'A'+10 : 0)))


// Convert a "%AB" or "%ab" hexadecimal string to its integer value, or return -1 if was not an hex string
static inline int url_DecodePercent(char *s) {
	if(	*s == '%'
	  	&& 	((*(s+1)>='0' &&  *(s+1)<='9') || (*(s+1)>='A' &&  *(s+1)<='F') || (*(s+1)>='a' &&  *(s+1)<='f'))
	  	&& 	((*(s+2)>='0' &&  *(s+2)<='9') || (*(s+2)>='A' &&  *(s+2)<='F') || (*(s+2)>='a' &&  *(s+2)<='f')) )
		return(16*VAL(*(s+1)) + VAL(*(s+2)));	
	else
		return(-1);
}


static char *url_RFC3986_ReservedChars = "!*'();:@&=+$,/?#[]";

static inline bool url_IsReserved(char c)
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
 * @param  new_len If not NULL, pointer to a long where the length of the
 *                 new string will be stored.
 * @return         Pointer to a newly allocated string, must be freed using
 *                 free(), or NULL in case of error.
 */
extern char *url_RemoveTabCRLF(char *string, long len, long *new_len)
{
	if(len==0)
		len=strlen(string);

	char *end_of_string = string + len - 1;

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
 * @param  new_len If not NULL, pointer to a long where the length of the modified
 *                 string will be stored.
 * @return         Pointer to the string, same as string argument.
 */
extern char *url_RemoveFragment(char *string, long *new_len)
{
	char *end = string;
	while(*end) {
		if(*end == '#') {
			*end = '\0';
			break;
		}
		end++;
	}
	if(new_len)
		*new_len = end - string;
	return(end);
}


/**
 * Percent-decode a string, calling itself until all percend-decoding is done.
 * Returned string is stored in a newly allocated buffer that needs to be freed.
 * @param  string  Pointer to string to be decoded.
 * @param  len     Length of string or 0. If len is 0, strlen() will be called.
 * @param  new_len Pointer to a long where to store length of the decoded string.
 *                 Can be NULL if you don't need the length of the returned string.
 * @return         Pointer to a newly allocated decoded string. Needs to be freed
 *                 with free(). NULL if error.
 */
extern inline char *url_Unescape(char *string, long len, long *new_len)
{

	// printf("Unescape() begin [%s] [%ld] [%ld]\n", string, len, (new_len ? *new_len : -1));

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

	long decoded_string_length = decoded_string - begin_decoded;
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
 * Normalize an URL. The URL must have been cleaned up before using url_RemoveTabCRLF(),
 * url_RemoveFragment() and url_Unescape() successively. Return a normalized URL in a 
 * newly allocated block of memory or NULL if error. WARNING : current limitation is 
 * that we don't do any normalization if the hostname is replaced by an IP address.
 * @param  src     Pointer to string holding the URL to be normalized.
 * @param  len     Length of source string. If 0, strlen() will be called.
 * @param  new_len If not NULL, pointer to a long where the length of the new string will be stored.
 * @return         Pointer to a newly allocated string. Must freed using free(). Or
 *                 NULL of error.
 */
extern char *url_Normalize(char *src, long len, long *new_len)
{
	if(len==0)
		len = strlen(src);
	// printf("url_Normalize() BEGIN src=[%s] len=%ld\n", src, len);
	
	// Save begining of source string
	char *begin_source = src;

	// Destination string cannot be longer that the initial string + "http://" + trailing '/'
	char *dest = malloc(len+1+8);
	if(dest==NULL)
		return(NULL);

	// Save the beginning of the destination string
	char *begin_dest = dest;

	// Copy the scheme part
	while(*src && *src!=':')
		*(dest++) = *(src++);

	if(*src=='\0') {
		// There is no scheme part, use "http" as default
		src = begin_source;
		dest = begin_dest;
		strcpy(dest, "http://");
		dest +=7;	
	} else if( *(src)==':' && *(src+1)=='/' && *(src+2)=='/') {
		// Copy the "://" part
		*(dest++) = *(src++); *(dest++) = *(src++); *(dest++) = *(src++);
	} else
		goto bad;

	// Find the next '/' so we can have the beginning and the end of the host name
	char *begin_hostname = src;
	while(*src && *src!='/')
		src++;
	src--;
	char *end_hostname = src;

	// Ignore leading dots
	while(*begin_hostname && *begin_hostname=='.')
		begin_hostname++;

	// Ignore trailing dots
	while(end_hostname-begin_hostname>0 && *end_hostname=='.')
		end_hostname--;

	// We should normalize the IP addresse, but we expect the IP address to be a 4 dot-separated decimal values
	
	// Copy the host name, making sure all characters are lowercase
	while(end_hostname-begin_hostname>=0) {
		*(dest++) = (*begin_hostname>='A' && *begin_hostname<='Z' ? *begin_hostname-'A'+'a' : *begin_hostname);
		begin_hostname++;
	}

	src++;
	*(dest++)='/';

	if(*src!='/') {
		*dest = '\0';
		goto good;
	}

	char *after_hostname = dest;

	bool in_query = false;
	while(*src) {
		if(in_query) {
			// If in query, just copy the character
			*(dest++) = *(src++);
		} else {
			// We are in the path
			switch(*src) {
				case '?':
					// Entering query
					*(dest++) = *(src++);
					in_query = true;
					break;
				case '/':
					if(*(src+1)=='.' && *(src+2)=='/') {
						// replace "/./" with "/"
						*(dest++) = '/';
						src +=3;
					} else if(*(src+1)=='.' && *(src+2)=='.' && (*(src+3)=='/' || *(src+3)=='\0')) {
						// Remove "/../" along with the preceding path component.
						if(*(src+3)=='\0')
							src +=3;
						else src +=4;
						do {
							dest--;
						} while(dest-after_hostname>=0 && *dest!='/');
						dest++;
					} else
						*(dest++) = *(src++);
					// Replace runs of consecutive slashes with a single slash character.
					if(*(dest-1)=='/' && *(dest-2)=='/')
						dest--;
					break;
				default:
					*(dest++) = *(src++);
			}
		}
	}
	*dest='\0';

good:
	if(new_len)
		*new_len = dest - begin_dest;
	// printf("url_Normalize() END dest=[%s] len=%ld\n", begin_dest, dest-begin_dest);
	return(begin_dest);

bad:
	if(dest)
		free(dest);
	return(NULL);
}

/**
 * Percent-encode a string to be used as an URL. Return the encoded URL in a
 * newly allocated buffer of NULL if error.
 * @param  src     Pointer to source string to be percent-encoded.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a long where the length of the new string will be stored.
 * @return         Pointer to newly allocated string. Must be freed with free().
 *                 Or NULL if error.
 */
extern char *url_Escape(char *src, long len, long *new_len)
{
	unsigned char *usrc = (unsigned char *)src;
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



extern char *url_EscapeIncludingReservedChars(char *src, long len, long *new_len)
{
	unsigned char *usrc = (unsigned char *)src;
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
 * Current limitation : no canonicalization of IP address is made.
 * Return canonicalized URL is a newly allocated buffer, or NULL if error.
 * @param  src     Pointer to source string holding the URL to be canonicalized.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a long where the length of the new string will be stored.
 * @return         Pointer to newly allocated string holding the canonicalized URL,
 *                 or NULL if error. Must be freed with free().
 */
extern char *url_Canonicalize(char *src, long len, long *new_len)
{
	long tmp;
	// printf("%-16s = [%s]\n", "SRC", src);
	if(new_len == NULL)
		new_len = &tmp;
	char *str1 = url_RemoveTabCRLF(src, len, new_len);
	// printf("%-16s = [%s]\n", "CLEANED", str1);
	// printf("new_len = %ld\n", *new_len);
	url_RemoveFragment(str1, new_len);
	// printf("%-16s = [%s]\n", "FRAGMENT REMOVED", str1);
	// printf("new_len = %ld\n", *new_len);	
	char *str2 = url_Unescape(str1, *new_len, new_len);
	// printf("%-16s = [%s]\n", "UNESCAPED", str2);
	// printf("new_len = %ld\n", *new_len);		
	char *str3 = url_Normalize(str2, *new_len, new_len);
	// printf("%-16s = [%s]\n", "NORMALIZED", str3);
	// printf("new_len = %ld\n", *new_len);	
	char *str4 = url_Escape(str3, *new_len, new_len);
	// printf("%-16s = [%s]\n", "ESCAPED", str4);
	// printf("new_len = %ld\n", *new_len);		
	free(str1);
	free(str2);
	free(str3);
	return(str4);
}


extern char *url_CanonicalizeWithFullEscape(char *src, long len, long *new_len)
{
	long tmp;
	// printf("%-16s = [%s]\n", "SRC", src);
	if(new_len == NULL)
		new_len = &tmp;
	char *str1 = url_RemoveTabCRLF(src, len, new_len);
	// printf("%-16s = [%s]\n", "CLEANED", str1);
	// printf("new_len = %ld\n", *new_len);
	url_RemoveFragment(str1, new_len);
	// printf("%-16s = [%s]\n", "FRAGMENT REMOVED", str1);
	// printf("new_len = %ld\n", *new_len);	
	char *str2 = url_Unescape(str1, *new_len, new_len);
	// printf("%-16s = [%s]\n", "UNESCAPED", str2);
	// printf("new_len = %ld\n", *new_len);		
	char *str3 = url_Normalize(str2, *new_len, new_len);
	// printf("%-16s = [%s]\n", "NORMALIZED", str3);
	// printf("new_len = %ld\n", *new_len);	
	char *str4 = url_EscapeIncludingReservedChars(str3, *new_len, new_len);
	// printf("%-16s = [%s]\n", "ESCAPED", str4);
	// printf("new_len = %ld\n", *new_len);		
	free(str1);
	free(str2);
	free(str3);
	return(str4);
}
