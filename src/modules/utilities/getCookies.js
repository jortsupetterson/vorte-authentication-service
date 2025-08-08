// shared/cookies.js

/**
 |======================|
 | @function getCookies  |
 |
 | Parses a Cookie header string into a key/value map.
 | @param {string} header
 | @returns {{ [cookieName: string]: string }}
 */
export function getCookies(header) {
	if (typeof header !== 'string') {
		throw new TypeError(`Expected header to be a string, but received ${typeof header}`);
	}
	return Object.fromEntries(
		header
			.split('; ')
			.filter(Boolean)
			.map((pair) => {
				const idx = pair.indexOf('=');
				const name = decodeURIComponent(pair.substring(0, idx));
				const value = decodeURIComponent(pair.substring(idx + 1));
				return [name, value];
			})
	);
}

let cryptoKeyPromise = null;
async function getCryptoKey(env) {
	if (!cryptoKeyPromise) {
		const raw = await env.COOKIES_ENC_KEY.get();
		const bytes = Uint8Array.from(atob(raw), (c) => c.charCodeAt(0));
		cryptoKeyPromise = crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
	}
	return cryptoKeyPromise;
}

/**
 |====================================|
 | @function getDecryptedCookie       |
 |
 | Decrypts a single cookie value blob.
 | @param {string} blob
 | @param {Env}    env
 | @returns {Promise<string|null>}
 */
export async function getDecryptedCookie(blob, env) {
	if (!blob) return null;
	const key = await getCryptoKey(env);
	const [ivB64, ctB64] = blob.split(':');
	const iv = Uint8Array.from(atob(ivB64), (c) => c.charCodeAt(0));
	const ct = Uint8Array.from(atob(ctB64), (c) => c.charCodeAt(0));
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
	return new TextDecoder().decode(pt);
}

export async function getEncryptedCookie(name, value, env, s) {
	const key = await getCryptoKey(env);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(value));

	const ivB64 = btoa(String.fromCharCode(...iv));
	const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ct)));
	const blob = `${ivB64}:${ctB64}`;

	let cookie = `${name}=${blob}; HttpOnly; Secure; SameSite=Strict; Path=/;`;
	if (typeof s === 'number' && s > 0) {
		const maxAge = s;
		cookie += ` Max-Age=${maxAge};`;
	}
	return cookie;
}
