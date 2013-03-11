#ifndef HEADER_CURL_TOOL_OAUTH2_H
#define HEADER_CURL_TOOL_OAUTH2_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <curl/oauth2.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * NAME curl_parse_oauth2_token()
 *
 * DESCRIPTION
 *
 * parses a string as an OAuth 2 token
 */
CURL_EXTERN CURLcode curl_parse_oauth2_token(const char *tokbuf,
                                             size_t tokbufsz,
                                             struct curl_oauth2_token *token);

CURL_EXTERN void curl_free_oauth2_token(struct curl_oauth2_token *token);

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_CURL_TOOL_OAUTH2_H */
