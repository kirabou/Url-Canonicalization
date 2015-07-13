#ifndef _URL_H_
#define _URL_H_

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
extern char *url_RemoveTabCRLF(char *string, long len, long *new_len);

/**
 * Remove the fragment part of an URL. For example, shorten 'http://google.com/#frag' 
 * to 'http://google.com/'. The initial string is changed by putting a NUL character
 * where the first '#' is found.
 * @param  string  Pointer to string holding the fragment.
 * @param  new_len If not NULL, pointer to a long where the length of the modified
 *                 string will be stored.
 * @return         Pointer to the string, same as string argument.
 */
extern char *url_RemoveFragment(char *string, long *new_len);

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
extern inline char *url_Unescape(char *string, long len, long *new_len);

/**
 * Normalize an URL. The URL must have been cleaned up before using url_RemoveTabCRLF(),
 * url_RemoveFragment() and url_Unescape() successively. Return a normalized URL in a 
 * newly allocated block of memory or NULL if error. WARNING : current limitation is 
 * that we don't do any normalization if the hostname is replaced by an IP address.
 * @param  src     Pointer to string holding the URL to be normalized.
 * @param  len     Length of source string. If 0, strlen() will be called.
 * @param  new_len If not NULL, pointer to a long where the length of the new string 
 *                 will be stored.
 * @return         Pointer to a newly allocated string. Must freed using free(). Or
 *                 NULL of error.
 */
extern char *url_Normalize(char *src, long len, long *new_len);

/**
 * Percent-encode a string to be used as an URL. Return the encoded URL in a
 * newly allocated buffer of NULL if error.
 * @param  src     Pointer to source string to be percent-encoded.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a long where the length of the new string 
 *                 will be stored.
 * @return         Pointer to newly allocated string. Must be freed with free().
 *                 Or NULL if error.
 */
extern char *url_Escape(char *src, long len, long *new_len);

/**
 * Canonicalize an URL as described in 
 * https://developers.google.com/safe-browsing/developers_guide_v3#Canonicalization.
 * Current limitation : no canonicalization of IP address is made.
 * Return canonicalized URL is a newly allocated buffer, or NULL if error.
 * @param  src     Pointer to source string holding the URL to be canonicalized.
 * @param  len     Length of source string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a long where the length of the new string 
 *                 will be stored.
 * @return         Pointer to newly allocated string holding the canonicalized URL,
 *                 or NULL if error. Must be freed with free().
 */
extern char *url_Canonicalize(char *src, long len, long *new_len);


#endif