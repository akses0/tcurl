/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl_mime.c
 * @brief Multipart/form-data MIME encoding for -F form support.
 *
 * Implements RFC 2046 multipart body generation for HTTP form submissions.
 */

#include "curl/curl_args.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Boundary generation constants */
#define BOUNDARY_PREFIX "----tcurlform"
#define BOUNDARY_RAND_LEN 16
#define BOUNDARY_MAX_LEN 64
#define BOUNDARY_DASHES_LEN 2 /* "--" prefix before boundary */

/* CRLF and line ending constants */
#define CRLF "\r\n"
#define CRLF_LEN 2
#define FINAL_BOUNDARY_SUFFIX_LEN 4 /* "--\r\n" after final boundary */

/* Buffer sizes */
#define MIME_HEADER_BUFFER_SIZE 512
#define MIME_READ_CHUNK_SIZE 16384

/* LCG constants (glibc-style) for fallback boundary generation */
#define LCG_MULTIPLIER 1103515245UL
#define LCG_INCREMENT 12345UL
#define LCG_EXTRACT_SHIFT 16

/* MIME type lookup table */
static const struct
{
  const char *ext;
  const char *mime;
} mime_types[] = {
  /* Images */
  { ".jpg", "image/jpeg" },
  { ".jpeg", "image/jpeg" },
  { ".png", "image/png" },
  { ".gif", "image/gif" },
  { ".webp", "image/webp" },
  { ".svg", "image/svg+xml" },
  { ".ico", "image/x-icon" },
  { ".bmp", "image/bmp" },

  /* Documents */
  { ".pdf", "application/pdf" },
  { ".doc", "application/msword" },
  { ".docx",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
  { ".xls", "application/vnd.ms-excel" },
  { ".xlsx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },

  /* Text */
  { ".txt", "text/plain" },
  { ".html", "text/html" },
  { ".htm", "text/html" },
  { ".css", "text/css" },
  { ".csv", "text/csv" },
  { ".xml", "application/xml" },

  /* Code */
  { ".js", "application/javascript" },
  { ".json", "application/json" },
  { ".c", "text/x-c" },
  { ".h", "text/x-c" },
  { ".py", "text/x-python" },

  /* Archives */
  { ".zip", "application/zip" },
  { ".tar", "application/x-tar" },
  { ".gz", "application/gzip" },
  { ".7z", "application/x-7z-compressed" },

  /* Audio/Video */
  { ".mp3", "audio/mpeg" },
  { ".wav", "audio/wav" },
  { ".mp4", "video/mp4" },
  { ".webm", "video/webm" },

  /* Sentinel */
  { NULL, "application/octet-stream" }
};

/**
 * @brief Multipart body streaming context.
 */
typedef struct
{
  const TcurlFormField *fields;
  int field_count;
  int current_field;
  char boundary[BOUNDARY_MAX_LEN];

  /* State machine for streaming */
  enum
  {
    MIME_STATE_BOUNDARY,
    MIME_STATE_HEADERS,
    MIME_STATE_BODY,
    MIME_STATE_BODY_CRLF,
    MIME_STATE_FINAL_BOUNDARY,
    MIME_STATE_DONE
  } state;

  /* Current field state */
  FILE *current_file;
  const char *current_data;
  size_t data_offset;
  size_t data_len;

  /* Header buffer for current field */
  char header_buf[MIME_HEADER_BUFFER_SIZE];
  size_t header_len;
  size_t header_offset;
} MimeContext;

/**
 * @brief Generate a random boundary string using /dev/urandom.
 *
 * Uses cryptographically secure random bytes to generate an unpredictable
 * boundary string as recommended by RFC 2046.
 */
void
Tcurl_mime_generate_boundary (char *boundary, size_t size)
{
  static const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  static const size_t charset_len = sizeof (charset) - 1;

  size_t prefix_len = strlen (BOUNDARY_PREFIX);
  if (size <= prefix_len + BOUNDARY_RAND_LEN)
    {
      boundary[0] = '\0';
      return;
    }

  memcpy (boundary, BOUNDARY_PREFIX, prefix_len);

  /* Read random bytes from /dev/urandom */
  unsigned char rand_bytes[BOUNDARY_RAND_LEN];
  int fd = open ("/dev/urandom", O_RDONLY);
  if (fd >= 0)
    {
      ssize_t nread = read (fd, rand_bytes, sizeof (rand_bytes));
      close (fd);

      if (nread == (ssize_t)sizeof (rand_bytes))
        {
          for (size_t i = 0; i < BOUNDARY_RAND_LEN; i++)
            boundary[prefix_len + i] = charset[rand_bytes[i] % charset_len];

          boundary[prefix_len + BOUNDARY_RAND_LEN] = '\0';
          return;
        }
    }

  /* Fallback: use PID and address-based entropy (not cryptographically secure) */
  unsigned long entropy = (unsigned long)getpid () ^ (unsigned long)boundary;
  for (size_t i = 0; i < BOUNDARY_RAND_LEN; i++)
    {
      entropy = entropy * LCG_MULTIPLIER + LCG_INCREMENT;
      boundary[prefix_len + i] = charset[(entropy >> LCG_EXTRACT_SHIFT) % charset_len];
    }

  boundary[prefix_len + BOUNDARY_RAND_LEN] = '\0';
}

/**
 * @brief Guess MIME type from filename extension.
 */
const char *
Tcurl_mime_guess_type (const char *filename)
{
  if (!filename)
    return "application/octet-stream";

  const char *dot = strrchr (filename, '.');
  if (!dot)
    return "application/octet-stream";

  for (int i = 0; mime_types[i].ext; i++)
    {
      if (strcasecmp (dot, mime_types[i].ext) == 0)
        return mime_types[i].mime;
    }

  return "application/octet-stream";
}

/**
 * @brief Extract filename from path.
 */
static const char *
get_basename (const char *path)
{
  if (!path)
    return NULL;

  const char *slash = strrchr (path, '/');
  if (slash)
    return slash + 1;

  return path;
}

/**
 * @brief Get file size, or -1 if cannot be determined.
 */
static ssize_t
get_file_size (const char *path)
{
  struct stat st;
  if (stat (path, &st) != 0)
    return -1;
  if (!S_ISREG (st.st_mode))
    return -1;
  return (ssize_t)st.st_size;
}

/**
 * @brief Calculate size of a single field's headers.
 */
static size_t
calc_field_header_size (const TcurlFormField *field, const char *boundary)
{
  /* Format:
   * --boundary\r\n
   * Content-Disposition: form-data; name="xxx"[; filename="xxx"]\r\n
   * [Content-Type: xxx\r\n]
   * \r\n
   */
  size_t size = 0;

  /* --boundary\r\n */
  size += BOUNDARY_DASHES_LEN + strlen (boundary) + CRLF_LEN;

  /* Content-Disposition header */
  size += strlen ("Content-Disposition: form-data; name=\"\"")
          + strlen (field->name) + CRLF_LEN;

  if (field->type == FORM_FIELD_FILE)
    {
      const char *filename
          = field->filename ? field->filename : get_basename (field->value);
      if (filename)
        size += strlen ("; filename=\"\"") + strlen (filename);
    }
  size += CRLF_LEN;

  /* Content-Type header for files */
  if (field->type == FORM_FIELD_FILE)
    {
      const char *ctype = field->content_type;
      if (!ctype)
        {
          const char *filename
              = field->filename ? field->filename : get_basename (field->value);
          ctype = Tcurl_mime_guess_type (filename);
        }
      size += strlen ("Content-Type: ") + strlen (ctype) + CRLF_LEN;
    }

  /* Empty line before body */
  size += CRLF_LEN;

  return size;
}

/**
 * @brief Safely add to total with overflow checking.
 *
 * @return 0 on success, -1 on overflow.
 */
static int
safe_add_size (ssize_t *total, ssize_t add)
{
  if (add < 0 || *total > SSIZE_MAX - add)
    return -1;
  *total += add;
  return 0;
}

/**
 * @brief Calculate total multipart body size.
 *
 * @return Body size in bytes, or -1 if size cannot be determined
 *         (e.g., file not found, not a regular file, or overflow).
 */
ssize_t
Tcurl_mime_body_size (const TcurlFormField *fields, int count,
                      const char *boundary)
{
  if (!fields || count <= 0 || !boundary)
    return -1;

  ssize_t total = 0;

  for (int i = 0; i < count; i++)
    {
      const TcurlFormField *field = &fields[i];

      /* Headers for this field */
      if (safe_add_size (&total, (ssize_t)calc_field_header_size (field, boundary)) < 0)
        return -1;

      /* Body content */
      if (field->type == FORM_FIELD_VALUE)
        {
          if (safe_add_size (&total, (ssize_t)strlen (field->value)) < 0)
            return -1;
        }
      else if (field->type == FORM_FIELD_FILE || field->type == FORM_FIELD_CONTENT)
        {
          ssize_t file_size = get_file_size (field->value);
          if (file_size < 0)
            return -1; /* Cannot determine size */
          if (safe_add_size (&total, file_size) < 0)
            return -1;
        }

      /* \r\n after body */
      if (safe_add_size (&total, CRLF_LEN) < 0)
        return -1;
    }

  /* Final boundary: --boundary--\r\n */
  ssize_t final_len = BOUNDARY_DASHES_LEN + (ssize_t)strlen (boundary)
                      + FINAL_BOUNDARY_SUFFIX_LEN;
  if (safe_add_size (&total, final_len) < 0)
    return -1;

  return total;
}

/**
 * @brief Build field headers into buffer.
 */
static size_t
build_field_headers (const TcurlFormField *field, const char *boundary,
                     char *buf, size_t buf_size)
{
  size_t offset = 0;
  int written;

  /* --boundary\r\n */
  written = snprintf (buf + offset, buf_size - offset, "--%s\r\n", boundary);
  if (written < 0 || (size_t)written >= buf_size - offset)
    return 0;
  offset += (size_t)written;

  /* Content-Disposition */
  if (field->type == FORM_FIELD_FILE)
    {
      const char *filename = field->filename ? field->filename : get_basename (field->value);
      written = snprintf (buf + offset, buf_size - offset,
                          "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n",
                          field->name, filename ? filename : "file");
    }
  else
    {
      written = snprintf (buf + offset, buf_size - offset,
                          "Content-Disposition: form-data; name=\"%s\"\r\n",
                          field->name);
    }
  if (written < 0 || (size_t)written >= buf_size - offset)
    return 0;
  offset += (size_t)written;

  /* Content-Type for files */
  if (field->type == FORM_FIELD_FILE)
    {
      const char *ctype = field->content_type;
      if (!ctype)
        {
          const char *filename = field->filename ? field->filename : get_basename (field->value);
          ctype = Tcurl_mime_guess_type (filename);
        }
      written = snprintf (buf + offset, buf_size - offset,
                          "Content-Type: %s\r\n", ctype);
      if (written < 0 || (size_t)written >= buf_size - offset)
        return 0;
      offset += (size_t)written;
    }

  /* Empty line */
  if (offset + CRLF_LEN >= buf_size)
    return 0;
  memcpy (buf + offset, CRLF, CRLF_LEN);
  offset += CRLF_LEN;

  return offset;
}

/**
 * @brief Build complete multipart body into buffer.
 *
 * This is the simple path for small forms that fit in memory.
 *
 * @return Bytes written, or -1 on error.
 */
ssize_t
Tcurl_mime_build_body (const TcurlFormField *fields, int count,
                       const char *boundary, char *output, size_t output_size)
{
  if (!fields || count <= 0 || !boundary || !output || output_size == 0)
    return -1;

  size_t offset = 0;

  for (int i = 0; i < count; i++)
    {
      const TcurlFormField *field = &fields[i];

      /* Write field headers */
      size_t header_len = build_field_headers (field, boundary,
                                               output + offset, output_size - offset);
      if (header_len == 0)
        return -1;
      offset += header_len;

      /* Write body */
      if (field->type == FORM_FIELD_VALUE)
        {
          size_t value_len = strlen (field->value);
          if (offset + value_len >= output_size)
            return -1;
          memcpy (output + offset, field->value, value_len);
          offset += value_len;
        }
      else if (field->type == FORM_FIELD_FILE || field->type == FORM_FIELD_CONTENT)
        {
          FILE *fp = fopen (field->value, "rb");
          if (!fp)
            {
              fprintf (stderr, "tcurl: Cannot open file: %s: %s\n",
                       field->value, strerror (errno));
              return -1;
            }

          char chunk[MIME_READ_CHUNK_SIZE];
          size_t nread;
          while ((nread = fread (chunk, 1, sizeof (chunk), fp)) > 0)
            {
              if (offset + nread >= output_size)
                {
                  fclose (fp);
                  return -1;
                }
              memcpy (output + offset, chunk, nread);
              offset += nread;
            }

          if (ferror (fp))
            {
              fprintf (stderr, "tcurl: Error reading file: %s: %s\n",
                       field->value, strerror (errno));
              fclose (fp);
              return -1;
            }
          fclose (fp);
        }

      /* \r\n after body */
      if (offset + CRLF_LEN >= output_size)
        return -1;
      memcpy (output + offset, CRLF, CRLF_LEN);
      offset += CRLF_LEN;
    }

  /* Final boundary: --boundary--\r\n */
  int written = snprintf (output + offset, output_size - offset,
                          "--%s--\r\n", boundary);
  if (written < 0 || (size_t)written >= output_size - offset)
    return -1;
  offset += (size_t)written;

  return (ssize_t)offset;
}

/**
 * @brief Create streaming MIME context.
 */
MimeContext *
Tcurl_mime_context_new (const TcurlFormField *fields, int count)
{
  if (!fields || count <= 0)
    return NULL;

  MimeContext *ctx = calloc (1, sizeof (MimeContext));
  if (!ctx)
    return NULL;

  ctx->fields = fields;
  ctx->field_count = count;
  ctx->current_field = 0;
  ctx->state = MIME_STATE_BOUNDARY;

  Tcurl_mime_generate_boundary (ctx->boundary, sizeof (ctx->boundary));

  return ctx;
}

/**
 * @brief Get boundary from context.
 */
const char *
Tcurl_mime_context_boundary (const MimeContext *ctx)
{
  return ctx ? ctx->boundary : NULL;
}

/**
 * @brief Free streaming MIME context.
 */
void
Tcurl_mime_context_free (MimeContext *ctx)
{
  if (!ctx)
    return;

  if (ctx->current_file)
    fclose (ctx->current_file);

  free (ctx);
}

/**
 * @brief Read callback for streaming multipart body.
 *
 * This implements a state machine that generates the multipart body
 * incrementally, suitable for use with CurlReadCallback.
 *
 * @return Number of bytes copied, 0 on EOF, or (size_t)-1 on error.
 */
size_t
Tcurl_mime_read_callback (void *buffer, size_t size, size_t nmemb,
                          void *userdata)
{
  MimeContext *ctx = (MimeContext *)userdata;
  if (!ctx || !buffer)
    return (size_t)-1;

  size_t buf_size = size * nmemb;
  if (buf_size == 0)
    return 0;

  char *out = (char *)buffer;
  size_t written = 0;

  while (written < buf_size && ctx->state != MIME_STATE_DONE)
    {
      switch (ctx->state)
        {
        case MIME_STATE_BOUNDARY:
          {
            /* Build headers for current field */
            if (ctx->current_field >= ctx->field_count)
              {
                ctx->state = MIME_STATE_FINAL_BOUNDARY;
                break;
              }

            const TcurlFormField *field = &ctx->fields[ctx->current_field];
            ctx->header_len = build_field_headers (field, ctx->boundary,
                                                   ctx->header_buf, sizeof (ctx->header_buf));
            ctx->header_offset = 0;
            ctx->state = MIME_STATE_HEADERS;
            break;
          }

        case MIME_STATE_HEADERS:
          {
            /* Copy headers to output buffer */
            size_t remaining = ctx->header_len - ctx->header_offset;
            size_t to_copy = buf_size - written;
            if (to_copy > remaining)
              to_copy = remaining;

            memcpy (out + written, ctx->header_buf + ctx->header_offset, to_copy);
            written += to_copy;
            ctx->header_offset += to_copy;

            if (ctx->header_offset >= ctx->header_len)
              {
                /* Prepare body */
                const TcurlFormField *field = &ctx->fields[ctx->current_field];
                if (field->type == FORM_FIELD_VALUE)
                  {
                    ctx->current_data = field->value;
                    ctx->data_len = strlen (field->value);
                    ctx->data_offset = 0;
                  }
                else
                  {
                    ctx->current_file = fopen (field->value, "rb");
                    if (!ctx->current_file)
                      {
                        fprintf (stderr, "tcurl: Cannot open file: %s: %s\n",
                                 field->value, strerror (errno));
                        return (size_t)-1;
                      }
                  }
                ctx->state = MIME_STATE_BODY;
              }
            break;
          }

        case MIME_STATE_BODY:
          {
            const TcurlFormField *field = &ctx->fields[ctx->current_field];

            if (field->type == FORM_FIELD_VALUE)
              {
                /* Copy string value */
                size_t remaining = ctx->data_len - ctx->data_offset;
                size_t to_copy = buf_size - written;
                if (to_copy > remaining)
                  to_copy = remaining;

                memcpy (out + written, ctx->current_data + ctx->data_offset, to_copy);
                written += to_copy;
                ctx->data_offset += to_copy;

                if (ctx->data_offset >= ctx->data_len)
                  {
                    ctx->state = MIME_STATE_BODY_CRLF;
                    ctx->data_offset = 0;
                  }
              }
            else
              {
                /* Read from file */
                size_t to_read = buf_size - written;
                size_t nread = fread (out + written, 1, to_read, ctx->current_file);
                written += nread;

                if (nread < to_read)
                  {
                    if (ferror (ctx->current_file))
                      {
                        fprintf (stderr, "tcurl: Error reading file: %s\n",
                                 strerror (errno));
                        return (size_t)-1;
                      }
                    /* EOF on file */
                    fclose (ctx->current_file);
                    ctx->current_file = NULL;
                    ctx->state = MIME_STATE_BODY_CRLF;
                    ctx->data_offset = 0;
                  }
              }
            break;
          }

        case MIME_STATE_BODY_CRLF:
          {
            /* Write \r\n after body */
            size_t remaining = CRLF_LEN - ctx->data_offset;
            size_t to_copy = buf_size - written;
            if (to_copy > remaining)
              to_copy = remaining;

            memcpy (out + written, CRLF + ctx->data_offset, to_copy);
            written += to_copy;
            ctx->data_offset += to_copy;

            if (ctx->data_offset >= CRLF_LEN)
              {
                ctx->current_field++;
                ctx->state = MIME_STATE_BOUNDARY;
              }
            break;
          }

        case MIME_STATE_FINAL_BOUNDARY:
          {
            /* Build and copy final boundary */
            if (ctx->header_offset == 0)
              {
                ctx->header_len = (size_t)snprintf (ctx->header_buf, sizeof (ctx->header_buf),
                                                    "--%s--\r\n", ctx->boundary);
              }

            size_t remaining = ctx->header_len - ctx->header_offset;
            size_t to_copy = buf_size - written;
            if (to_copy > remaining)
              to_copy = remaining;

            memcpy (out + written, ctx->header_buf + ctx->header_offset, to_copy);
            written += to_copy;
            ctx->header_offset += to_copy;

            if (ctx->header_offset >= ctx->header_len)
              ctx->state = MIME_STATE_DONE;
            break;
          }

        case MIME_STATE_DONE:
          /* Should not reach here */
          break;
        }
    }

  return written;
}
