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

#if !defined(CURL_DISABLE_OAUTH2) && !defined(CURL_DISABLE_HTTP)

#include "urldata.h"
#include "sendf.h"
#include "rawstr.h"
#include "curl_base64.h"
#include "curl_hmac.h"
#include "http_oauth2.h"
#include "http.h"
#include "strtok.h"
#include "url.h" /* for Curl_safefree() */
#include "curl_memory.h"
#include "non-ascii.h" /* included for Curl_convert_... prototypes */
#include "warnless.h"

#include <curl/oauth2.h>

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

#define MAX_VALUE_LENGTH 256
#define MAX_CONTENT_LENGTH 1024

#if !defined(CURL_DISABLE_HTTPMAC) && !defined(CURL_DISABLE_CRYPTO_AUTH)

const HMAC_params Curl_HMAC_SHA1[] = {
  {
    (HMAC_hinit_func) SHA1_Init,           /* Hash initialization function. */
    (HMAC_hupdate_func) SHA1_Update,       /* Hash update function. */
    (HMAC_hfinal_func) SHA1_Final,         /* Hash computation end function. */
    sizeof(SHA_CTX),                      /* Size of hash context structure. */
    64,                                   /* Maximum key length. */
    20                                    /* Result size. */
  }
};

const HMAC_params Curl_HMAC_SHA256[] = {
  {
    (HMAC_hinit_func) SHA256_Init,        /* Hash initialization function. */
    (HMAC_hupdate_func) SHA256_Update,    /* Hash update function. */
    (HMAC_hfinal_func) SHA256_Final,      /* Hash computation end function. */
    sizeof(SHA256_CTX),                   /* Size of hash context structure. */
    64,                                   /* Maximum key length. */
    32                                    /* Result size. */
  }
};

#endif

CURLcode Curl_output_oauth2(struct connectdata *conn,
                         bool proxy,
                         const unsigned char *request,
                         const unsigned char *uripath)
{
  /* Please refer to draft-ietf-oauth-v2-http-mac for all the juicy
     details about HTTP MAC construction. */

  struct SessionHandle *data = conn->data;
  struct curl_oauth2_token *token = data->set.oauth2token;
  CURLcode rc;

  /* Check that we have an OAuth 2.0 token. */

  if(!token) {
    return CURLE_OAUTH2_TOKEN_MALFORMAT;
  }

  /* Output the proper authorization header depending on the token type. */

  switch(token->token_type) {
  case CURL_OAUTH2_TOKEN_TYPE_INVALID:
    rc = CURLE_OAUTH2_TOKEN_MALFORMAT;
    break;
#if !defined(CURL_DISABLE_HTTPMAC) && !defined(CURL_DISABLE_CRYPTO_AUTH)
  case CURL_OAUTH2_TOKEN_TYPE_MAC:
    rc = Curl_output_mac(conn, proxy, request, uripath, token);
    break;
#endif
  case CURL_OAUTH2_TOKEN_TYPE_BEARER:
    rc = Curl_output_bearer(conn, proxy, request, uripath, token);
    break;
  default:
    rc = CURLE_OAUTH2_TOKEN_TYPE_UNSUPPORTED;
    break;
  }

  return rc;
}

#if !defined(CURL_DISABLE_HTTPMAC) && !defined(CURL_DISABLE_CRYPTO_AUTH)

/* HTTP MAC requires that timestamps are monotically increasing from
   a fixed origin (across invocations). It however does not specify
   that origin. Defining CURL_ENABLE_HTTPMAC_RECENT_EPOCH is an easy
   way to test that your favorite OAuth 2.0 server respects arbitrary
   origins.

   Defining DELTA_EPOCH_IN_SECS to a relatively large value is a good
   way to expose bugs in server-side HTTP MAC timestamp validation.
   Defining it to something larger than the difference between the date
   of calling and the Epoch is a mistake... */
#ifdef CURL_ENABLE_HTTPMAC_RECENT_EPOCH
#define DELTA_EPOCH_IN_SECS 1023667200L
#endif

/*
 * Output an HTTP MAC Authorization header.
 */
CURLcode Curl_output_mac(struct connectdata *conn,
                         bool proxy,
                         const unsigned char *request,
                         const unsigned char *uripath,
                         struct curl_oauth2_token *token)
{
  /* Please refer to draft-ietf-oauth-v2-http-mac for all the juicy
     details about HTTP MAC construction. */

  struct timeval now;
  char ts[12];
  char nonce[33];
  long nonceval = 0;
  size_t noncesz = 0;
  char *nreq = NULL;
  char **allocuserpwd;
  struct auth *authp;
  struct SessionHandle *data = conn->data;
  const char *hosthdr = NULL, *hosthdrp1 = NULL, *hosthdrp2 = NULL;
  char *hostname = NULL;
  unsigned long port = 0;
  const char *ext = data->set.str[STRING_HTTP_MAC_EXT];
  bool extprovided = (ext != 0);
  char *extinfo;
  const HMAC_params *params;
  HMAC_context *ctxt;
  char digest[32];            /* The max of result_len is enough. */
  char *mac = NULL;
  size_t macsz = 0;
  CURLcode rc;
/* The CURL_OUTPUT_MAC_CONV macro below is for non-ASCII machines.
   It converts digest text to ASCII so the MAC will be correct for
   what ultimately goes over the network.
*/
#define CURL_OUTPUT_MAC_CONV(a, b) \
  rc = Curl_convert_to_network(a, (char *)b, strlen((const char*)b)); \
  if(rc != CURLE_OK) { \
    free(b); \
    goto cleanup; \
  }

  /* Check that we have the proper kind of token. */

  if(token->token_type != CURL_OAUTH2_TOKEN_TYPE_MAC) {
    return CURLE_OAUTH2_TOKEN_MALFORMAT;
  }

  /* Select the right Authorization field to fill in depending on
     whether we're talking to a proxy or the remote host. */

  if(proxy) {
    allocuserpwd = &conn->allocptr.proxyuserpwd;
    authp = &data->state.authproxy;
  }
  else {
    allocuserpwd = &conn->allocptr.userpwd;
    authp = &data->state.authhost;
  }

  if(*allocuserpwd) {
    Curl_safefree(*allocuserpwd);
    *allocuserpwd = NULL;
  }

  authp->done = TRUE;

  /* Generate a timestamp from a monotically increasing source whose
     origin does not change. */

  now = curlx_tvgettimeofday();
#ifdef DELTA_EPOCH_IN_SECS
  now.tv_sec -= DELTA_EPOCH_IN_SECS;
#endif
  snprintf(ts, sizeof(ts) - 1, "%ld", (long)now.tv_sec);
  ts[sizeof(ts) - 1] = '\0';

  /* Generate a nonce that is unique for that timestamp */

  nonceval = (long)now.tv_sec + now.tv_usec;
  for(noncesz = 0; nonceval && noncesz < sizeof(nonce) - 1; ++noncesz) {
    int base = "\x08\x10\x0a\x1a"[noncesz % 4];
    nonce[noncesz] = "0123456789abcdefghijklmnopqrstuvwxyz"[nonceval % base];
    nonceval /= base;
  }
  nonce[noncesz] = '\0';

  /* Find hostname and port in headers, do not use the connection data. */

  hosthdr = conn->allocptr.host;
  if(!hosthdr) {
    hosthdr = Curl_checkheaders(data, "Host:");
  }
  if(!hosthdr) {
    rc = CURLE_HTTP_MAC_INVALID_HOST;
    goto cleanup;
  }

  /* Copy the hostname port of the Host header. */

  for(hosthdrp1 = hosthdr + 5; *hosthdrp1 && ISSPACE(*hosthdrp1); ++hosthdrp1);
  for(hosthdrp2 = hosthdrp1; *hosthdrp2 && *hosthdrp2 != ':'
        && !ISSPACE(*hosthdrp2); ++hosthdrp2);
  if(hosthdrp2 - hosthdrp1 == 0) {
    rc = CURLE_HTTP_MAC_INVALID_HOST;
    goto cleanup;
  }
  hostname = calloc(1, hosthdrp2 - hosthdrp1 + 1);
  if(!hostname) {
    rc = CURLE_OUT_OF_MEMORY;
    goto cleanup;
  }
  strncpy(hostname, hosthdrp1, hosthdrp2 - hosthdrp1);

  /* Check for a port in the Host header, and if we find it makes sure that
     it is well formed. If not, take the connection's port. */

  for(hosthdrp1 = hosthdrp2 = (hosthdrp2 + (*hosthdrp2 ? 1 : 0));
       *hosthdrp2 && ISDIGIT(*hosthdrp2); ++hosthdrp2);
  if(hosthdrp2 - hosthdrp1) {
    char *rest;
    port = strtoul(hosthdrp1, &rest, 10);  /* Must be decimal */
    if(rest != (hosthdrp1 + 1) && !*rest) {
      if(port > 0xffff) {   /* Single unix standard says port numbers are
                              * 16 bits long */
        rc = CURLE_HTTP_MAC_INVALID_HOST;
        goto cleanup;
      }
    }
  }
  else {
    port = conn->remote_port;
  }

  /* Any non-space character found in the Host field after the hostname
     and port makes that header invalid. */

  for(; *hosthdrp2 && ISSPACE(*hosthdrp2); ++hosthdrp2);
  if(*hosthdrp2) {
    rc = CURLE_HTTP_MAC_INVALID_HOST;
    goto cleanup;
  }

  /* Now generate the normalized request. See the I-D for details of the
     fields that get into there. All fields are separated by a newline
     defined as %0a (ASCII 10). If an "ext" field was not provided,
     include an empty one. */

  if(!ext) {
    ext = "";
  }
  nreq = aprintf("%s\x0a%s\x0a%s\x0a%s\x0a%s\x0a%lu\x0a%s\x0a",
                 ts,
                 nonce,
                 request,
                 uripath,
                 hostname,
                 port,
                 ext);
  if(!nreq) {
    rc = CURLE_OUT_OF_MEMORY;
    goto cleanup;
  }
  CURL_OUTPUT_MAC_CONV(data, nreq);

  /* Pick appropriate parameters to run the HMAC on the normalized
     request. */

  switch (token->mac_token.mac_algo) {
  case CURL_OAUTH2_MAC_ALGO_HMAC_SHA1:
    params = Curl_HMAC_SHA1;
    break;
  case CURL_OAUTH2_MAC_ALGO_HMAC_SHA256:
    params = Curl_HMAC_SHA256;
    break;
  default:
    rc = CURLE_OAUTH2_TOKEN_MALFORMAT;
    goto cleanup;
  }

  /* Compute the MAC using the MAC token key. */

  ctxt = Curl_HMAC_init(params,
                        (const unsigned char *)token->mac_token.mac_key,
                        curlx_uztoui(strlen(token->mac_token.mac_key)));
  if(!ctxt) {
    rc = CURLE_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Update the MAC with the normalized request. */

  Curl_HMAC_update(ctxt, (const unsigned char *)nreq,
                   curlx_uztoui(strlen(nreq)));

  /* Finalise the MAC */
  Curl_HMAC_final(ctxt, (unsigned char *)digest);

  /* Base64-encode the mac to produce the request MAC. */

  rc = Curl_base64_encode(data, digest, (*params).hmac_resultlen,
                            &mac, &macsz);
  if(rc)
    goto cleanup;

  /* Produce the Authorization header. The header contains the computed
     MAC, of course, but also all the other information needed by a server
     to run HMAC on the same normalized request. The server uses the same
     MAC secret and algorithm since the client and server both have a copy
     of the MAC token (identified here by the "id" field).

     We omit the "ext" field if it was not given to us. We always put it
     there if it was provided, even if it's empty. */

  if(extprovided) {
    extinfo = aprintf("ext=\"%s\", ", ext);
  }
  else {
    extinfo = "";
  }

  *allocuserpwd =
    aprintf( "Authorization: MAC "
             "id=\"%s\", "
             "ts=\"%s\", "
             "nonce=\"%s\", "
             "%s"
             "mac=\"%s\"\n", token->access_token, ts, nonce, extinfo, mac);

  if(!*allocuserpwd) {
    rc = CURLE_OUT_OF_MEMORY;
    goto cleanup;
  }
  CURL_OUTPUT_MAC_CONV(data, allocuserpwd);

  rc = CURLE_OK;

  /* Cleanup allocated memory. */

  cleanup:
  if(extprovided) Curl_safefree(extinfo);
  Curl_safefree(mac);
  Curl_safefree(hostname);
  Curl_safefree(nreq);

  return rc;
}

#endif

/*
 * Output a Bearer Authorization header.
 */
CURLcode Curl_output_bearer(struct connectdata *conn,
                         bool proxy,
                         const unsigned char *request,
                         const unsigned char *uripath,
                         struct curl_oauth2_token *token)
{
  char **allocuserpwd;
  struct auth *authp;
  struct SessionHandle *data = conn->data;
  CURLcode rc;
/* The CURL_OUTPUT_BEARER_CONV macro below is for non-ASCII machines.
   It converts digest text to ASCII so the MAC will be correct for
   what ultimately goes over the network.
*/
#define CURL_OUTPUT_BEARER_CONV(a, b) \
  rc = Curl_convert_to_network(a, (char *)b, strlen((const char*)b)); \
  if(rc != CURLE_OK) { \
    free(b); \
    return rc; \
  }

  (void)request;
  (void)uripath;

  /* Check that we have the proper kind of token. */

  if(token->token_type != CURL_OAUTH2_TOKEN_TYPE_BEARER) {
    return CURLE_OAUTH2_TOKEN_MALFORMAT;
  }

  /* Select the right Authorization field to fill in depending on
     whether we're talking to a proxy or the remote host. */

  if(proxy) {
    allocuserpwd = &conn->allocptr.proxyuserpwd;
    authp = &data->state.authproxy;
  }
  else {
    allocuserpwd = &conn->allocptr.userpwd;
    authp = &data->state.authhost;
  }

  if(*allocuserpwd) {
    Curl_safefree(*allocuserpwd);
    *allocuserpwd = NULL;
  }

  authp->done = TRUE;

  /* Produce the Authorization header. It is a very trivial header that
     simply communicates the identifier of the bearer token. */

  *allocuserpwd =
    aprintf( "Authorization: Bearer %s\n", token->access_token);
  if(!*allocuserpwd) {
    return CURLE_OUT_OF_MEMORY;
  }
  CURL_OUTPUT_BEARER_CONV(data, allocuserpwd);

  return CURLE_OK;
}

#endif
