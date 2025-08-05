import { getDecryptedCookie } from './getCookies.j';
export async function parseAuthenticationCookie(encryptedCookie) {
	const decryptedCookie = await getDecryptedCookie(encryptedCookie);
	const ready = decryptedCookie.split(';');
	return ready;
}
