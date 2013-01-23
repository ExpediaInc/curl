#ifndef HEADER_CURL_HTTP_OAUTH2_H
#define HEADER_CURL_HTTP_OAUTH2_H
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
#include "curl_setup.h"

struct curl_oauth2_token;

enum {
  CURLMACALGO_SHA1,
  CURLMACALGO_SHA256
};

/* this is for creating an OAuth 2 header output */
CURLcode Curl_output_oauth2(struct connectdata *conn,
                         bool proxy,
                         const unsigned char *request,
                         const unsigned char *uripath);

/* this is for creating a MAC header output */
CURLcode Curl_output_mac(struct connectdata *conn,
                         bool proxy,
                         const unsigned char *request,
                         const unsigned char *uripath,
                         struct curl_oauth2_token *token);

/* this is for creating a Bearer header output */
CURLcode Curl_output_bearer(struct connectdata *conn,
                         bool proxy,
                         const unsigned char *request,
                         const unsigned char *uripath,
                         struct curl_oauth2_token *token);

#endif /* HEADER_CURL_HTTP_OAUTH2_H */
