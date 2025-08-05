/**
 |=======================|
 | @function getEightDigits |
 |
 | Generates a secure Eight-digit numeric code.
 |
 | Uses the Web Crypto API to generate a 32-bit random number,
 | maps it to a number in the range [000000–999999], and returns it
 | as a zero-padded string. Suitable for OTPs, 2FA codes, etc.
 |
 | @returns {string}
 |   A string with exactly Eight digits (e.g., "042381").
 |
 */
export default function getEightDigits() {
	const array = new Uint32Array(1);
	crypto.getRandomValues(array);
	const code = array[0] % 100_000_000;
	return code.toString().padStart(8, '0');
}
