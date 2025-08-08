import { getDecryptedCookie } from './getCookies.js';
export async function parseAuthenticationCookie(encryptedCookie) {
	const decryptedCookie = await getDecryptedCookie(encryptedCookie);
	const ready = decryptedCookie.split(';');
	return ready;
}
