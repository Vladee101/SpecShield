// Aliases appearing inside strings and comments must survive a sanitize/restore
// round trip untouched. SERVICE_H7K2Q3 in this comment is not an identity.
export const DOCS_URL = "https://docs.example.test/SERVICE_H7K2Q3";
export const TEMPLATE = `subscription ${"DTO_M4X2Q7"} was created`;

// Not aliases: SCREAMING_SNAKE constants have no digit in the final segment.
export const MAX_RETRIES = 5;
export const DEFAULT_TIMEOUT = 30_000;
export const HTTP_OK = 200;
