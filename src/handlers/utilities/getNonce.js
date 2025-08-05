/**
 * Generates a cryptographically secure random nonce.
 *
 * This function creates a 16-byte random value using the Web Crypto API,
 * converts each byte to a character, and returns the result encoded
 * in Base64. Ideal for use in security headers (e.g., Content Security Policy).
 *
 * @returns {string}
 *   A Base64-encoded string representing a 16-byte random nonce.
 */
export default function getNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let str = "";
  for (const b of bytes) {
    str += String.fromCharCode(b);
  }
  return btoa(str);
}
