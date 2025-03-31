/* jwt.c */
#include "jwt.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

/* Forward declarations for internal helper functions */
static char *base64url_encode(const unsigned char *input, int length);
static unsigned char *base64url_decode(const char *input, int *out_len);
static char *create_header_json(const jwt_header_t *header);
static char *create_payload_json(const jwt_payload_t *payload);
static char *compute_signature(const char *data, const char *secret);
static char *json_get_string(const char *json, const char *key);
static int json_get_number(const char *json, const char *key, long *number);

/* Replace '+' with '-' and '/' with '_' and remove '=' padding */
static char *base64url_encode(const unsigned char *input, int length) {
    /* Use EVP_EncodeBlock to do standard base64 encoding */
    int encoded_len = 4 * ((length + 2) / 3);
    unsigned char *b64 = malloc(encoded_len + 1);
    if (!b64) return NULL;
    EVP_EncodeBlock(b64, input, length);
    b64[encoded_len] = '\0';

    /* Replace characters and remove padding */
    for (int i = 0; i < encoded_len; i++) {
        if (b64[i] == '+')
            b64[i] = '-';
        else if (b64[i] == '/')
            b64[i] = '_';
    }
    /* Remove '=' padding */
    int pad = 0;
    for (int i = encoded_len - 1; i >= 0 && b64[i] == '='; i--) {
        b64[i] = '\0';
        pad++;
    }
    char *result = strdup((char *)b64);
    free(b64);
    return result;
}

/* Decode a base64url string into a newly allocated buffer.
 * out_len is set to the length of the decoded data.
 */
static unsigned char *base64url_decode(const char *input, int *out_len) {
    int len = strlen(input);
    /* Make a copy so we can modify it */
    char *b64 = malloc(len + 5); // extra space for padding and null
    if (!b64) return NULL;
    strcpy(b64, input);
    for (int i = 0; i < len; i++) {
        if (b64[i] == '-')
            b64[i] = '+';
        else if (b64[i] == '_')
            b64[i] = '/';
    }
    /* Calculate the required padding */
    int mod = len % 4;
    if (mod != 0) {
        int pad = 4 - mod;
        for (int i = 0; i < pad; i++) {
            strcat(b64, "=");
        }
    }
    int b64_len = strlen(b64);
    unsigned char *decoded = malloc(b64_len);
    if (!decoded) {
        free(b64);
        return NULL;
    }
    int decoded_len = EVP_DecodeBlock(decoded, (unsigned char *)b64, b64_len);
    free(b64);
    if (decoded_len < 0) {
        free(decoded);
        return NULL;
    }
    /* Note: EVP_DecodeBlock may include extra bytes from padding */
    *out_len = decoded_len;
    return decoded;
}

/* Create a JSON string for the header.
 * Expected format: {"alg":"<alg>","typ":"<typ>"}
 */
static char *create_header_json(const jwt_header_t *header) {
    int size = snprintf(NULL, 0, "{\"alg\":\"%s\",\"typ\":\"%s\"}", header->alg, header->typ);
    char *json = malloc(size + 1);
    if (!json) return NULL;
    sprintf(json, "{\"alg\":\"%s\",\"typ\":\"%s\"}", header->alg, header->typ);
    return json;
}

/* Create a JSON string for the payload.
 * Expected format: {"sub":"<sub>","iss":"<iss>","exp":<exp>}
 */
static char *create_payload_json(const jwt_payload_t *payload) {
    int size = snprintf(NULL, 0, "{\"sub\":\"%s\",\"iss\":\"%s\",\"exp\":%ld}", payload->sub, payload->iss, (long)payload->exp);
    char *json = malloc(size + 1);
    if (!json) return NULL;
    sprintf(json, "{\"sub\":\"%s\",\"iss\":\"%s\",\"exp\":%ld}", payload->sub, payload->iss, (long)payload->exp);
    return json;
}

/* Compute HMAC-SHA256 signature and return base64url-encoded string.
 * The returned string must be freed by the caller.
 */
static char *compute_signature(const char *data, const char *secret) {
    unsigned int sig_len;
    unsigned char sig[EVP_MAX_MD_SIZE];

    if (!HMAC(EVP_sha256(), secret, (int)strlen(secret),
              (unsigned char *)data, strlen(data),
              sig, &sig_len))
        return NULL;

    char *sig_encoded = base64url_encode(sig, sig_len);
    return sig_encoded;
}

/* Helper: extract a string value for a given key from a JSON string.
 * This very basic parser looks for "<key>":"<value>".
 * Caller must free the returned string.
 */
static char *json_get_string(const char *json, const char *key) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    char *start = strstr(json, pattern);
    if (!start) return NULL;
    start += strlen(pattern);
    char *end = strchr(start, '"');
    if (!end) return NULL;
    int len = end - start;
    char *value = malloc(len + 1);
    if (!value) return NULL;
    strncpy(value, start, len);
    value[len] = '\0';
    return value;
}

/* Helper: extract a numeric value for a given key from a JSON string.
 * Looks for "<key>":<number>
 */
static int json_get_number(const char *json, const char *key, long *number) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    char *start = strstr(json, pattern);
    if (!start) return -1;
    start += strlen(pattern);
    if (sscanf(start, "%ld", number) != 1)
        return -1;
    return 0;
}

/* Encode a JWT token.
 * See header for details.
 */
int jwt_encode(const char *secret, const jwt_header_t *header, const jwt_payload_t *payload, char **token) {
    if (!secret || !header || !payload || !token)
        return 1;

    char *header_json = create_header_json(header);
    char *payload_json = create_payload_json(payload);
    if (!header_json || !payload_json) {
        free(header_json);
        free(payload_json);
        return 1;
    }

    char *header_b64 = base64url_encode((unsigned char *)header_json, (int)strlen(header_json));
    char *payload_b64 = base64url_encode((unsigned char *)payload_json, (int)strlen(payload_json));
    free(header_json);
    free(payload_json);
    if (!header_b64 || !payload_b64) {
        free(header_b64);
        free(payload_b64);
        return 1;
    }

    /* Create data string: header.payload */
    int data_len = strlen(header_b64) + 1 + strlen(payload_b64) + 1;
    char *data = malloc(data_len);
    if (!data) {
        free(header_b64);
        free(payload_b64);
        return 1;
    }
    sprintf(data, "%s.%s", header_b64, payload_b64);

    /* Compute signature */
    char *signature_b64 = compute_signature(data, secret);
    if (!signature_b64) {
        free(header_b64);
        free(payload_b64);
        free(data);
        return 1;
    }

    /* Allocate final token: header.payload.signature */
    int token_len = strlen(header_b64) + 1 + strlen(payload_b64) + 1 + strlen(signature_b64) + 1;
    *token = malloc(token_len);
    if (!*token) {
        free(header_b64);
        free(payload_b64);
        free(signature_b64);
        free(data);
        return 1;
    }
    sprintf(*token, "%s.%s.%s", header_b64, payload_b64, signature_b64);

    free(header_b64);
    free(payload_b64);
    free(signature_b64);
    free(data);
    return 0;
}

/* Decode a JWT token.
 * See header for details.
 */
int jwt_decode(const char *secret, const char *token, jwt_header_t **header, jwt_payload_t **payload) {
    if (!secret || !token || !header || !payload)
        return 1;

    char *token_copy = strdup(token);
    if (!token_copy)
        return 1;

    char *parts[3] = {0};
    char *saveptr = NULL;
    char *token_part = strtok_r(token_copy, ".", &saveptr);
    int i = 0;
    while (token_part && i < 3) {
        parts[i++] = token_part;
        token_part = strtok_r(NULL, ".", &saveptr);
    }
    if (i != 3) {
        free(token_copy);
        return 1;
    }

    /* Duplicate each part so that we don't depend on token_copy's lifetime */
    char *header_part = strdup(parts[0]);
    char *payload_part = strdup(parts[1]);
    char *sig_part = strdup(parts[2]);
    free(token_copy);
    if (!header_part || !payload_part || !sig_part) {
        free(header_part);
        free(payload_part);
        free(sig_part);
        return 1;
    }

    /* Recompute signature */
    int data_len = strlen(header_part) + 1 + strlen(payload_part) + 1;
    char *data = malloc(data_len);
    if (!data) {
        free(header_part);
        free(payload_part);
        free(sig_part);
        return 1;
    }
    sprintf(data, "%s.%s", header_part, payload_part);
    char *computed_sig = compute_signature(data, secret);
    free(data);
    if (!computed_sig) {
        free(header_part);
        free(payload_part);
        free(sig_part);
        return 1;
    }
    if (strcmp(computed_sig, sig_part) != 0) {
        free(computed_sig);
        free(header_part);
        free(payload_part);
        free(sig_part);
        return 1;
    }
    free(computed_sig);
    free(sig_part);

    /* Decode header and payload JSON */
    int header_json_len, payload_json_len;
    unsigned char *header_json_u = base64url_decode(header_part, &header_json_len);
    unsigned char *payload_json_u = base64url_decode(payload_part, &payload_json_len);
    free(header_part);
    free(payload_part);
    if (!header_json_u || !payload_json_u) {
        free(header_json_u);
        free(payload_json_u);
        return 1;
    }
    char *header_json = malloc(header_json_len + 1);
    char *payload_json = malloc(payload_json_len + 1);
    if (!header_json || !payload_json) {
        free(header_json_u);
        free(payload_json_u);
        free(header_json);
        free(payload_json);
        return 1;
    }
    memcpy(header_json, header_json_u, header_json_len);
    header_json[header_json_len] = '\0';
    memcpy(payload_json, payload_json_u, payload_json_len);
    payload_json[payload_json_len] = '\0';
    free(header_json_u);
    free(payload_json_u);

    /* Parse header JSON */
    char *alg = json_get_string(header_json, "alg");
    char *typ = json_get_string(header_json, "typ");
    free(header_json);
    if (!alg || !typ) {
        free(alg);
        free(typ);
        free(payload_json);
        return 1;
    }
    jwt_header_t *hdr = malloc(sizeof(jwt_header_t));
    if (!hdr) {
        free(alg);
        free(typ);
        free(payload_json);
        return 1;
    }
    hdr->alg = alg;
    hdr->typ = typ;

    /* Parse payload JSON */
    char *sub = json_get_string(payload_json, "sub");
    char *iss = json_get_string(payload_json, "iss");
    long exp;
    if (json_get_number(payload_json, "exp", &exp) != 0) {
        free(sub);
        free(iss);
        free(payload_json);
        free(hdr);
        return 1;
    }
    free(payload_json);
    jwt_payload_t *pld = malloc(sizeof(jwt_payload_t));
    if (!pld) {
        free(sub);
        free(iss);
        free(hdr);
        return 1;
    }
    pld->sub = sub;
    pld->iss = iss;
    pld->exp = (time_t)exp;

    /* Check expiration */
    time_t now = time(NULL);
    if (now > pld->exp) {
        jwt_free_header(hdr);
        jwt_free_payload(pld);
        return 1;
    }

    *header = hdr;
    *payload = pld;
    return 0;
}

/* Free a jwt_header_t structure */
void jwt_free_header(jwt_header_t *header) {
    if (header) {
        free(header->alg);
        free(header->typ);
        free(header);
    }
}

/* Free a jwt_payload_t structure */
void jwt_free_payload(jwt_payload_t *payload) {
    if (payload) {
        free(payload->sub);
        free(payload->iss);
        free(payload);
    }
}
