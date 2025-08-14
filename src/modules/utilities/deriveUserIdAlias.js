/**
 * @param {string} signInMethod  // "email" | "sms" | "google" | "microsoft" | ...
 * @param {string} subject       // emailAddress | phoneNumber | providerSubject
 * @param {string} serverSecretB64 // base64-encoded 32B secret (SERVER_SALT)
 * @returns {Promise<string>} stable alias, e.g. "u1:email:7E1q...".
 */
export async function deriveUserIdAlias(signInMethod, subject, serverSecretB64) {
	const parts = [signInMethod, subject].map((x) =>
		String(x ?? '')
			.normalize('NFC')
			.trim()
			.toLowerCase()
	);

	// Lossless canonical data for MAC
	const data = new TextEncoder().encode(parts.join('\x1F'));

	// Import HMAC key from base64
	const secret = Uint8Array.from(atob(serverSecretB64), (c) => c.charCodeAt(0));
	const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

	// MAC(data) -> base64url, lyhennä esim. 20 tavuun aliasia varten
	const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
	const short = base64url(mac.slice(0, 20)); // 27 merkkiä

	// Versioi ja pidä metodi näkyvissä debugia varten
	return `u1:${parts[0]}:${short}`;
}

function base64url(bytes) {
	let s = btoa(String.fromCharCode(...bytes));
	return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
