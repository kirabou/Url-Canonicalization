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
extern char *url_RemoveTabCRLF(const char *string, size_t len, size_t *new_len);

/**
 * Remove the fragment part of an URL. For example, shorten 'http://google.com/#frag' 
 * to 'http://google.com/'. The initial string is changed by putting a NUL character
 * where the first '#' is found.
 * @param  string  Pointer to string holding the fragment.
 * @param  new_len If not NULL, pointer to a size_t where the length of the modified
 *                 string will be stored.
 * @return         Pointer to the string, same as string argument.
 */
extern char *url_RemoveFragment(char *string, size_t *new_len);

/**
 * Remove the query part of an URL (part starting with ?). The initial
 * string is changed by putting a NUL character where the first '?' is found.
 * @param  string  Pointer to a string holding the URL.
 * @param  new_len Pointer to size_t. If not NULL, will be loaded with
 *                 the new length of the shortened URL.
 * @return         Pointer to query part if found, or NULL.
 */
extern char *url_RemoveQuery(char *string, size_t *new_len);

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
extern char *url_Unescape(const char *string, size_t len, size_t *new_len);

/**
 * Normalize an URL. The URL will be cleaned with url_RemoveTabCRLF(), then its 
 * fragments will be removed with url_RemoveFragment(). The URL will be unescaped
 * with url_Unescape() before being normalizes. Return a normalized URL in a 
 * newly allocated block of memory or NULL if error. 
 * @param  src     Pointer to string holding the URL to be normalized.
 * @param  len     Length of source string. If 0, strlen() will be called.
 * @param  new_len If not NULL, pointer to a size_t where the length of the new string will be stored.
 * @return         Pointer to a newly allocated string. Must freed using free(). Or
 *                 NULL of error.
 */
extern char *url_Normalize(const char *src, const size_t len, size_t *new_len);

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
extern char *url_Escape(const char *src, size_t len, size_t *new_len);

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
extern char *url_EscapeIncludingReservedChars(const char *src, size_t len, size_t *new_len);

/**
 * Encode a string to be compliant with application/x-www-form-urlencoded format.
 * It is the same as url_EscapeIncludingReservedChars() but it also replaces 
 * spaces with '+'.
 * @param  src     Pointer to string to be encoded.
 * @param  len     Length of string. If 0, strlen() will be used.
 * @param  new_len If not NULL, pointer to a size_t where the length of the 
 *                 encoded string will be stored.
 * @return         Pointer to newly allocated string holding 
 *                 or NULL if error. Must be freed with free().
 */
extern char *url_Encode(const char *src, size_t len, size_t *new_len);

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
extern char *url_Canonicalize(const char *src, size_t len, size_t *new_len);

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
extern char *url_CanonicalizeWithFullEscape(const char *src, size_t len, size_t *new_len);

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
extern char *url_ParseNextKeyValuePair(char *string, char **key_string, char **value_string, const char *separators_list);

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
extern void url_Split(char *url, char **scheme, char **link, char **query);


/**
 * Return the hostname part extracted from an url in a newly allocated string.
 * @param  url     Pointer to an URL.
 * @return         Pointer to a newly allocated string holding the hostname
 *                 extracted from the URL. Use free() to deallocate the memory.
 */
extern char *url_GetHostname(const char *url);

/**
 * Return the hostname part extracted from an url in a newly allocated string,
 * without skiping the www. header.
 * @param  url     Pointer to an URL.
 * @return         Pointer to a newly allocated string holding the hostname
 *                 extracted from the URL. Use free() to deallocate the memory.
 */
extern char *url_GetHostnameWWW(const char *url);

/**
 * Return the base part of an URL in a newly allocated string.
 * @param  url     Pointer to string holding the URL.
 * @param  len     Length of URL, strlen() will be used if 0.
 * @param  new_len If not NULL, pointer to a size_t where the length of the new
 *                 string will be stored.
 * @return         Pointer to a newly allocated string holding the
 *                 base part of the initial URL.
 */
extern char *url_GetBase(const char *url, size_t len, size_t *new_len);


/**
 * Return the scheme part of an URL in a newly allocated string
 * @param  url Pointer to string holding the URL.
 * @return     Pointer to a newly allocated string holding the
 *             scheme part of the initial URL.
 */
extern char *url_GetScheme(const char *url);


/**
 * Test if a given URL is absolute (ie. starting with http:// or https://).
 * @param  url URL to be tested.
 * @return     true if the URL is absolute, or false.
 */
extern bool url_IsAbsolute(const char *url);


/**
 * Make an absolute URL in a newly allocated memory string. If the given
 * URL is already absolute, a simple copy is made.
 * @param  parent_url Parent URL from which the "absolute" part will be
 *                    extracted. Must be absolute, obviously.
 * @param  url        Absolute or relative URL from which an absolute one
 *                    must be built. The "absolute" is built based on the
 *                    given parent_url.
 * @return            Newly allocated string holding the absolute url for
 *                    the given URL, or NULL if error.
 */
extern char *url_MakeAbsolute(const char *parent_url, const char *url);


/**
 * Skip the scheme part of an URL. Return pointer to first
 * character in the URL after the scheme part, or pointer to
 * first character in URL if no scheme found.
 * @param  url Pointer to string holding the URL.
 * @return     Pointer to first character in the URL after the
 *             scheme part, or pointer to first character in 
 *             URL if no scheme part found.
 */
extern const char *url_SkipScheme(const char *url);


/**
 * Skip the wwww. part of a scheme less URL.
 * @param  url_schemeless Pointer to a scheme less URL
 * @return                Pointer into url_schemless where
 *                        the "www." part ends.
 */
extern const char *url_SkipWWW(const char *url_schemeless);


/**
 * Get fragment of an unescaped URL in a newly allocated string.
 * @param  url Pointer to unescaped URL.
 * @return     Pointer to fragment part of the URL in a newly allocated
 *             buffer, or NULL if none found. The returned buffer
 *             must be free()
 */
extern char *url_GetFragment(const char *url);



#endif