#ifndef JWT_H
#define JWT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>

/* JWT header structure */
typedef struct {
    char *alg;  /* algorithm, e.g. "HS256" */
    char *typ;  /* type, e.g. "JWT" */
} jwt_header_t;

/* JWT payload structure */
typedef struct {
    char *sub;  /* subject */
    char *iss;  /* issuer */
    time_t exp; /* expiration time (unix timestamp) */
} jwt_payload_t;

/* 
 * Encodes a JWT token.
 * Parameters:
 *  - secret: the HMAC secret key.
 *  - header: pointer to a jwt_header_t structure.
 *  - payload: pointer to a jwt_payload_t structure.
 *  - token: on success, will be allocated to hold the JWT string.
 * Caller is responsible for freeing *token.
 * Returns 0 on success, nonzero on failure.
 */
int jwt_encode(const char *secret, const jwt_header_t *header, const jwt_payload_t *payload, char **token);

/* 
 * Decodes a JWT token.
 * Parameters:
 *  - secret: the HMAC secret key.
 *  - token: the JWT string.
 *  - header: on success, will point to a newly allocated jwt_header_t structure.
 *  - payload: on success, will point to a newly allocated jwt_payload_t structure.
 * The token’s signature is verified and the expiration time is checked.
 * Returns 0 on success, nonzero on failure.
 */
int jwt_decode(const char *secret, const char *token, jwt_header_t **header, jwt_payload_t **payload);

/* Free functions for decoded structures */
void jwt_free_header(jwt_header_t *header);
void jwt_free_payload(jwt_payload_t *payload);

#ifdef __cplusplus
}
#endif

#endif /* JWT_H */
