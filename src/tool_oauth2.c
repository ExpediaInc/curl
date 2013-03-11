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
#include "escape.h"
#include "memdebug.h"

#include <stdio.h>

#if HAVE_JSONSL
#define JSONSL_STATE_GENERIC
#include <jsonsl.h>
#endif

#include "tool_oauth2.h"

#define CURL_OAUTH2_TOKEN_FILE_BUFSZ 2048

struct NameValue {
  const char *name;
  int value;
};

static const struct NameValue token_nv_TOKENTYPES[] = {
  { "bearer", CURL_OAUTH2_TOKEN_TYPE_BEARER },
#if !defined(CURL_DISABLE_HTTPMAC) && !defined(CURL_DISABLE_CRYPTO_AUTH)
  { "mac", CURL_OAUTH2_TOKEN_TYPE_MAC },
#endif
  { 0, 0 }
};

#if !defined(CURL_DISABLE_HTTPMAC) && !defined(CURL_DISABLE_CRYPTO_AUTH)

static const struct NameValue token_nv_MACALGOS[] = {
  { "hmac-sha-1", CURL_OAUTH2_MAC_ALGO_HMAC_SHA1 },
  { "hmac-sha-256", CURL_OAUTH2_MAC_ALGO_HMAC_SHA256 },
  { 0, 0 }
};

#endif

static CURLcode set_token_property(struct curl_oauth2_token *token,
                                   const char *key, size_t key_len,
                                   const char *val, size_t val_len) {
  CURLcode rc = CURLE_OK;
  if(key_len == 12 &&
     !strncmp("access_token", key, 12)) {
    char *dupstr = malloc(val_len + 1);
    if(dupstr) {
      strncpy(dupstr, val, val_len);
      dupstr[val_len] = '\0';
      token->access_token = dupstr;
    }
    else {
      rc = CURLE_OUT_OF_MEMORY;
    }
  }
  else if(key_len == 10 &&
          !strncmp(key, "token_type", 10)) {
    const struct NameValue *nvlist;
    for(nvlist = token_nv_TOKENTYPES; nvlist->name; ++nvlist) {
      if((val_len = strlen(nvlist->name)) != 0
         && !strncmp(val, nvlist->name, val_len)) {
        break;
      }
    }
    if(nvlist->name) {
      token->token_type = nvlist->value;
    }
    else {
      token->token_type = CURL_OAUTH2_TOKEN_TYPE_INVALID;
      rc = CURLE_OAUTH2_TOKEN_TYPE_UNSUPPORTED;
    }
  }
#if !defined(CURL_DISABLE_HTTPMAC) && !defined(CURL_DISABLE_CRYPTO_AUTH)
  else if(key_len == 7 &&
          !strncmp(key, "mac_key", 7)) {
    char *dupstr = malloc(val_len + 1);
    if(dupstr) {
      strncpy(dupstr, val, val_len);
      dupstr[val_len] = '\0';
      token->mac_token.mac_key = dupstr;
    }
    else {
      rc = CURLE_OUT_OF_MEMORY;
    }
  }
  else if(key_len == 13 &&
          !strncmp(key, "mac_algorithm", 13)) {
    const struct NameValue *nvlist;
    for(nvlist = token_nv_MACALGOS; nvlist->name; ++nvlist) {
      if((val_len = strlen(nvlist->name)) != 0
         && !strncmp(val, nvlist->name, val_len)) {
        break;
      }
    }
    if(nvlist->name) {
      token->mac_token.mac_algo = nvlist->value;
    }
    else {
      token->mac_token.mac_algo = CURL_OAUTH2_MAC_ALGO_INVALID;
      rc = CURLE_HTTP_MAC_ALGO_UNSUPPORTED;
    }
  }
#endif

  return rc;
}

static CURLcode parse_oauth2_urlencoded(const char *tokstr, size_t tokstrlen,
                                        struct curl_oauth2_token *token) {
  const char *end = tokstr + tokstrlen;
  const char *tokstrp1, *tokstrp2;

  if(tokstrlen && tokstr[tokstrlen - 1] == '&') {
    return CURLE_OAUTH2_TOKEN_MALFORMAT;
  }

  for(tokstrp1 = tokstr; tokstrp1 < end; ++tokstrp1) {
    CURLcode rc;
    const char *keyenc, *valenc;
    char *key = NULL, *val = NULL;
    size_t keyenc_len, key_len, valenc_len, val_len;

    for(tokstrp2 = tokstrp1; tokstrp2 < end && *tokstrp2 != '=' &&
           *tokstrp2 != '&'; ++tokstrp2);
    keyenc_len = tokstrp2 - tokstrp1;
    if(!keyenc_len) {
      return CURLE_OAUTH2_TOKEN_MALFORMAT;
    }
    keyenc = tokstrp1;
    key = curl_easy_unescape_form(NULL, keyenc, keyenc_len, &key_len);
    if(key == NULL) {
      return CURLE_OAUTH2_TOKEN_MALFORMAT; /* It could be a memory error
                                              too but we cannot tell... */
    }

    if(tokstrp2 < end && *tokstrp2 != '&') {
      for(tokstrp1 = tokstrp2 + 1; tokstrp2 < end && *tokstrp2 != '&';
          ++tokstrp2);
    }
    else {
      tokstrp1 = tokstrp2;
    }
    valenc_len = tokstrp2 - tokstrp1;
    if(!valenc_len) {
      val = calloc(1, sizeof(char));
      if(!val) {
        free(key);
        return CURLE_OUT_OF_MEMORY;
      }
    }
    else {
      valenc = tokstrp1;
      val = curl_easy_unescape_form(NULL, valenc, valenc_len, &val_len);
      if(val == NULL) {
        free(key);
        return CURLE_OAUTH2_TOKEN_MALFORMAT; /* It could be a memory error
                                                too but we cannot tell... */
      }
    }

    rc = set_token_property(token, key, key_len, val, val_len);
    free(key);
    free(val);

    if(rc != CURLE_OK) {
      return rc;
    }

    tokstrp1 = tokstrp2;
  }

  return CURLE_OK;
}

#if HAVE_JSONSL

struct jsonsl_token_data {
  CURLcode ccode;
  char *key;
  size_t key_len;
  struct curl_oauth2_token *token;
};

static int parse_error_callback(jsonsl_t jsn,
                                jsonsl_error_t err,
                                struct jsonsl_state_st *state,
                                char *errat) {
  struct jsonsl_token_data *datap = jsn->data;
  datap->ccode = CURLE_OAUTH2_TOKEN_MALFORMAT;

  (void)jsn;
  (void)err;
  (void)state;
  (void)errat;

  return 0;
}

static void parse_state_callback(jsonsl_t jsn,
                                 jsonsl_action_t action,
                                 struct jsonsl_state_st *state,
                                 const char *buf) {

  struct jsonsl_token_data *datap = jsn->data;

  (void)action;

  switch(state->level) {
  case 1:
    if(state->type != JSONSL_T_OBJECT) {
      datap->ccode = CURLE_OAUTH2_TOKEN_MALFORMAT;
    }
    break;

  case 2:
    if(state->type == JSONSL_T_HKEY) {
      /* we allocate a string for the key so we can work across buffer
         boundaries later if we decide to implement a streaming model */
      char *dupstr;
      Curl_safefree(datap->key);
      dupstr = malloc(state->pos_cur - state->pos_begin + 1);
      if(!dupstr) {
        datap->ccode = CURLE_OUT_OF_MEMORY;
      }
      else {
        strncpy(dupstr, buf - state->pos_cur + state->pos_begin + 1,
                state->pos_cur - state->pos_begin - 1);
        dupstr[state->pos_cur - state->pos_begin - 1] = '\0';
        datap->key = dupstr;
        datap->key_len = state->pos_cur - state->pos_begin - 1;
      }
    }
    else if(state->type == JSONSL_T_STRING) {
      /* check if the key for that string is one that is meaningful for
         an OAuth 2.0 token we support, and if so, store its value */
      const char *key = datap->key;
      size_t key_len = datap->key_len;
      size_t val_start = state->pos_begin + 1;
      size_t val_len = state->pos_cur - val_start;
      const char *val = buf - state->pos_cur + val_start;

      datap->ccode = set_token_property(datap->token, key, key_len,
                                        val, val_len);
    }
    break;
  default:
    state->ignore_callback = 1;
    break;
  }

  if(datap->ccode != CURLE_OK) {
    state->ignore_callback = 1;
  }
}

static CURLcode parse_oauth2_json(const char *tokstr, size_t tokstrlen,
                                  struct curl_oauth2_token *token) {
  jsonsl_t jsn;
  struct jsonsl_token_data data = { CURLE_OK, NULL, 0, NULL };
  data.token = token;

  jsn = jsonsl_new(5);          /* we only want one nesting level */
  if(!jsn) {
    return CURLE_OUT_OF_MEMORY;
  }

  jsn->data = &data;
  jsn->error_callback = parse_error_callback;
  jsn->action_callback = NULL;
  jsn->action_callback_POP = parse_state_callback;

  jsonsl_enable_all_callbacks(jsn);

  jsonsl_feed(jsn, tokstr, tokstrlen);

  jsonsl_destroy(jsn);

  Curl_safefree(data.key);

  /* bail if parsing was not successful */

  if(data.ccode != CURLE_OK) {
    return data.ccode;
  }

  /* validate the token data we got during parsing */

  switch(token->token_type) {
  case CURL_OAUTH2_TOKEN_TYPE_INVALID:
    return CURLE_OAUTH2_TOKEN_MALFORMAT;
  case CURL_OAUTH2_TOKEN_TYPE_BEARER:
    if(!token->access_token) {
      return CURLE_OAUTH2_TOKEN_MALFORMAT;
    }
    break;
  case CURL_OAUTH2_TOKEN_TYPE_MAC:
    if(!token->mac_token.mac_key) {
      return CURLE_OAUTH2_TOKEN_MALFORMAT;
    }
    if(token->mac_token.mac_algo == CURL_OAUTH2_MAC_ALGO_INVALID) {
      return CURLE_OAUTH2_TOKEN_MALFORMAT;
    }
    break;
  }

  return CURLE_OK;
}

#else

static CURLcode parse_oauth2_json(const char *tokstr, size_t tokstrlen,
                                  struct curl_oauth2_token *token) {
  return CURLE_OAUTH2_TOKEN_MALFORMAT;
}

#endif /* HAVE_JSONSL */

CURLcode curl_parse_oauth2_token(const char *tokbuf, size_t tokbufsz,
                                 struct curl_oauth2_token *token) {

  const char *cp;
  CURLcode rc;

  /* determine the token file format and parse it */

  for(cp = tokbuf; (size_t) (cp - tokbuf) < tokbufsz && ISSPACE(*cp); ++cp);
  if((size_t) (cp - tokbuf) < tokbufsz && *cp == '{') {
    rc = parse_oauth2_json(cp, tokbufsz - (cp - tokbuf), token);
  }
  else {
    rc = parse_oauth2_urlencoded(cp, tokbufsz - (cp - tokbuf), token);
  }

  return rc;
}

void curl_free_oauth2_token(struct curl_oauth2_token *token) {
    char *cp = (char *)token->access_token;
    Curl_safefree(cp);
#ifndef CURL_DISABLE_HTTPMAC
  switch(token->token_type) {
  case CURL_OAUTH2_TOKEN_TYPE_MAC:
      cp = (char *)token->mac_token.mac_key;
      Curl_safefree(cp);
    break;
  default:
    break;
  }
#endif
}

#endif

