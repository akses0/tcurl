/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl_redirect.c
 * @brief HTTP redirect handling for curl module.
 *
 * Implements redirect following with proper HTTP semantics:
 * - 301/302: POST→GET transformation (legacy behavior)
 * - 303: Always GET
 * - 307/308: Preserve original method
 * - Cross-origin redirect handling
 * - Redirect count limiting
 */

#include "curl/StreamingCurl-private.h"
#include "curl/StreamingCurl.h"
#include "http/SocketHTTP.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* URL protocol prefix lengths */
#define HTTP_PROTOCOL_PREFIX_LEN 7  /* "http://" */
#define HTTPS_PROTOCOL_PREFIX_LEN 8 /* "https://" */

/**
 * @brief Check if a header name is security-sensitive.
 *
 * These headers should be stripped on cross-origin redirects to prevent
 * credential leakage to third-party domains.
 *
 * @param name Header name
 * @return 1 if sensitive, 0 otherwise
 */
static int
is_sensitive_header (const char *name)
{
  if (!name)
    return 0;

  /* Authorization headers */
  if (strcasecmp (name, "Authorization") == 0)
    return 1;
  if (strcasecmp (name, "Proxy-Authorization") == 0)
    return 1;

  /* Cookie headers */
  if (strcasecmp (name, "Cookie") == 0)
    return 1;

  /* Common API key headers */
  if (strcasecmp (name, "X-API-Key") == 0)
    return 1;
  if (strcasecmp (name, "X-Auth-Token") == 0)
    return 1;
  if (strcasecmp (name, "X-Access-Token") == 0)
    return 1;
  if (strcasecmp (name, "X-Secret-Key") == 0)
    return 1;

  /* AWS headers */
  if (strncasecmp (name, "X-Amz-", 6) == 0)
    return 1;

  /* Azure headers */
  if (strcasecmp (name, "X-Ms-Authorization-Auxiliary") == 0)
    return 1;

  return 0;
}

/**
 * @brief Filter sensitive headers from custom headers list.
 *
 * Removes headers that could leak credentials to third-party domains.
 * Modifies the list in-place.
 *
 * @param headers Pointer to head of custom headers list
 */
static void
filter_sensitive_custom_headers (CurlCustomHeader **headers)
{
  if (!headers || !*headers)
    return;

  CurlCustomHeader *prev = NULL;
  CurlCustomHeader *current = *headers;

  while (current)
    {
      if (is_sensitive_header (current->name))
        {
          /* Remove this header from the list */
          if (prev)
            prev->next = current->next;
          else
            *headers = current->next;

          /* Move to next without updating prev */
          current = current->next;
        }
      else
        {
          prev = current;
          current = current->next;
        }
    }
}

/**
 * @brief Check if status code is a redirect.
 *
 * @param status HTTP status code
 * @return 1 if redirect, 0 otherwise
 */
static int
is_redirect_status (int status)
{
  return (status == CURL_HTTP_STATUS_MOVED_PERMANENTLY || status == CURL_HTTP_STATUS_FOUND || status == CURL_HTTP_STATUS_SEE_OTHER || status == CURL_HTTP_STATUS_TEMPORARY_REDIRECT
          || status == CURL_HTTP_STATUS_PERMANENT_REDIRECT);
}

/**
 * @brief Determine if method should be changed to GET.
 *
 * According to HTTP specs:
 * - 301/302: POST→GET (legacy browser behavior, widely adopted)
 * - 303: Always change to GET
 * - 307/308: Preserve original method
 *
 * @param status Redirect status code
 * @param method Original request method
 * @return 1 if should change to GET, 0 otherwise
 */
static int
should_change_method_to_get (int status, SocketHTTP_Method method)
{
  /* 303 See Other: always GET */
  if (status == CURL_HTTP_STATUS_SEE_OTHER)
    return 1;

  /* 301/302: POST becomes GET (legacy behavior) */
  if ((status == CURL_HTTP_STATUS_MOVED_PERMANENTLY || status == CURL_HTTP_STATUS_FOUND) && method == HTTP_METHOD_POST)
    return 1;

  /* 307/308: preserve method */
  return 0;
}

/**
 * @brief Check if two hosts match (case-insensitive).
 *
 * @param host1 First hostname
 * @param len1 Length of first hostname
 * @param host2 Second hostname
 * @param len2 Length of second hostname
 * @return 1 if match, 0 otherwise
 */
static int
hosts_match (const char *host1, size_t len1, const char *host2, size_t len2)
{
  if (len1 != len2)
    return 0;

  for (size_t i = 0; i < len1; i++)
    {
      if (tolower ((unsigned char)host1[i])
          != tolower ((unsigned char)host2[i]))
        return 0;
    }

  return 1;
}

int
curl_is_redirect (CurlSession_T session)
{
  if (!session)
    return 0;

  int status = session->response.status_code;
  return is_redirect_status (status);
}

int
curl_redirect_status (CurlSession_T session)
{
  if (!session)
    return 0;

  return session->response.status_code;
}

const char *
curl_redirect_location (CurlSession_T session)
{
  if (!session || !session->response.headers)
    return NULL;

  return SocketHTTP_Headers_get (session->response.headers, "Location");
}

int
curl_redirect_changes_method (CurlSession_T session)
{
  if (!session)
    return 0;

  int status = session->response.status_code;
  return should_change_method_to_get (status, session->request_method);
}

SocketHTTP_Method
curl_redirect_method (CurlSession_T session)
{
  if (!session)
    return HTTP_METHOD_GET;

  int status = session->response.status_code;

  if (should_change_method_to_get (status, session->request_method))
    return HTTP_METHOD_GET;

  return session->request_method;
}

int
curl_redirect_preserves_body (CurlSession_T session)
{
  if (!session)
    return 0;

  int status = session->response.status_code;

  /* 307/308 preserve body */
  return (status == CURL_HTTP_STATUS_TEMPORARY_REDIRECT || status == CURL_HTTP_STATUS_PERMANENT_REDIRECT);
}

int
curl_redirect_is_cross_origin (CurlSession_T session, const char *location)
{
  if (!session || !location)
    return 0;

  /* Parse the location URL */
  CurlParsedURL new_url;
  CurlError err = curl_internal_parse_url (location, 0, &new_url,
                                           session->request_arena);

  /* If parsing fails, treat as relative URL (same origin) */
  if (err != CURL_OK)
    return 0;

  /* Compare with current URL */
  return !curl_urls_same_origin (&session->current_url, &new_url);
}

ssize_t
curl_resolve_redirect_url (CurlSession_T session, const char *location,
                           char *output, size_t output_size)
{
  if (!session || !location || !output || output_size == 0)
    return -1;

  /* If location is absolute URL, use as-is */
  if (strncasecmp (location, "http://", HTTP_PROTOCOL_PREFIX_LEN) == 0
      || strncasecmp (location, "https://", HTTPS_PROTOCOL_PREFIX_LEN) == 0)
    {
      size_t len = strlen (location);
      if (len >= output_size)
        return -1;

      memcpy (output, location, len);
      output[len] = '\0';
      return (ssize_t)len;
    }

  /* Otherwise, resolve relative to current URL */
  return Curl_resolve_url (&session->current_url, location, output,
                           output_size);
}

int
curl_parse_redirect_url (CurlSession_T session, const char *location,
                         CurlParsedURL *result)
{
  if (!session || !location || !result)
    return -1;

  char resolved[CURL_MAX_URL_BUFFER_LEN];
  ssize_t len = curl_resolve_redirect_url (session, location, resolved,
                                           sizeof (resolved));
  if (len < 0)
    return -1;

  CurlError err = curl_internal_parse_url (resolved, (size_t)len, result,
                                           session->request_arena);
  if (err != CURL_OK)
    return -1;

  return 0;
}

int
curl_should_follow_redirect (CurlSession_T session)
{
  if (!session)
    return 0;

  /* Check if redirects are enabled */
  if (!session->options.follow_redirects)
    return 0;

  /* Check if this is a redirect response */
  if (!curl_is_redirect (session))
    return 0;

  /* Check redirect limit */
  if ((int)session->response.redirect_count >= session->options.max_redirects)
    return 0;

  /* Check for Location header */
  const char *location = curl_redirect_location (session);
  if (!location || *location == '\0')
    return 0;

  return 1;
}

CurlError
curl_prepare_redirect (CurlSession_T session)
{
  if (!session)
    return CURL_ERROR_CONNECT;

  /* Get location header */
  const char *location = curl_redirect_location (session);
  if (!location)
    return CURL_ERROR_PROTOCOL;

  /* Parse the new URL */
  CurlParsedURL new_url;
  if (curl_parse_redirect_url (session, location, &new_url) != 0)
    return CURL_ERROR_INVALID_URL;

  /* Security check: Block HTTPS to HTTP redirects (TLS downgrade) */
  if (session->current_url.is_secure && !new_url.is_secure)
    {
      session->state = CURL_STATE_ERROR;
      session->last_error = CURL_ERROR_INSECURE_REDIRECT;
      return CURL_ERROR_INSECURE_REDIRECT;
    }

  /* Check if this is cross-origin */
  int cross_origin = !curl_urls_same_origin (&session->current_url, &new_url);

  /* Security: Strip sensitive data on cross-origin redirects */
  if (cross_origin)
    {
      /* Inhibit authentication for this redirect chain (issue #6)
       * We set a flag rather than clearing session->auth so that:
       * 1. Credentials are preserved for future requests to original domain
       * 2. curl_auth_setup() knows to skip regeneration during redirects
       * The flag is reset in Curl_session_reset() for new requests */
      session->auth_header = NULL;
      session->auth_inhibited = 1;

      /* Filter sensitive custom headers (issue #7) */
      filter_sensitive_custom_headers (&session->custom_headers);
    }

  /* Determine new method */
  SocketHTTP_Method new_method = curl_redirect_method (session);

  /* If cross-origin or method changes, close existing connection */
  if (cross_origin || (new_method != session->request_method))
    {
      if (session->conn && !curl_connection_reusable (session->conn, &new_url))
        {
          curl_connection_close (session->conn);
          session->conn = NULL;
        }
    }

  /* Update session state */
  curl_url_copy (&session->current_url, &new_url, session->request_arena);
  SocketHTTP_Method original_method = session->request_method;
  session->request_method = new_method;
  session->response.redirect_count++;

  /* Clear request body for GET redirects (303 or 301/302 from POST) */
  if (new_method == HTTP_METHOD_GET && original_method != HTTP_METHOD_GET)
    {
      session->upload_total = 0;
      session->upload_sent = 0;
    }

  /* Reset state for new request */
  session->state = CURL_STATE_IDLE;

  return CURL_OK;
}

CurlError
curl_handle_redirect (CurlSession_T session)
{
  if (!session)
    return CURL_ERROR_CONNECT;

  /* Check if this is a redirect response */
  if (!curl_is_redirect (session))
    return CURL_OK;

  /* Check if redirects are enabled */
  if (!session->options.follow_redirects)
    return CURL_OK;

  /* Check redirect limit - return error if at limit */
  if ((int)session->response.redirect_count >= session->options.max_redirects)
    {
      session->state = CURL_STATE_ERROR;
      session->last_error = CURL_ERROR_TOO_MANY_REDIRECTS;
      return CURL_ERROR_TOO_MANY_REDIRECTS;
    }

  /* Check for Location header */
  const char *location = curl_redirect_location (session);
  if (!location || *location == '\0')
    return CURL_OK;

  /* Prepare for redirect */
  return curl_prepare_redirect (session);
}

int
curl_get_redirect_count (CurlSession_T session)
{
  if (!session)
    return 0;

  return (int)session->response.redirect_count;
}

int
curl_redirect_is_secure_downgrade (CurlSession_T session, const char *location)
{
  if (!session || !location)
    return 0;

  /* Parse the location URL */
  CurlParsedURL new_url;
  char resolved[CURL_MAX_URL_BUFFER_LEN];
  ssize_t len = curl_resolve_redirect_url (session, location, resolved,
                                           sizeof (resolved));
  if (len < 0)
    return 0;

  CurlError err = curl_internal_parse_url (resolved, (size_t)len, &new_url,
                                           session->request_arena);
  if (err != CURL_OK)
    return 0;

  /* Check if going from HTTPS to HTTP */
  return (session->current_url.is_secure && !new_url.is_secure);
}

int
curl_redirect_is_same_host (CurlSession_T session, const char *location)
{
  if (!session || !location)
    return 0;

  /* Parse the location URL */
  CurlParsedURL new_url;
  char resolved[CURL_MAX_URL_BUFFER_LEN];
  ssize_t len = curl_resolve_redirect_url (session, location, resolved,
                                           sizeof (resolved));
  if (len < 0)
    return 1; /* Relative URL = same host */

  CurlError err = curl_internal_parse_url (resolved, (size_t)len, &new_url,
                                           session->request_arena);
  if (err != CURL_OK)
    return 1; /* Parsing failed = assume same host */

  /* Compare hosts */
  return hosts_match (session->current_url.host, session->current_url.host_len,
                      new_url.host, new_url.host_len);
}

void
curl_reset_redirect_count (CurlSession_T session)
{
  if (!session)
    return;

  session->response.redirect_count = 0;
}
