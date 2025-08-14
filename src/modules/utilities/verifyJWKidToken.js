function b64urlToBytes(s) {
	s = s.replace(/-/g, '+').replace(/_/g, '/');
	if (s.length % 4) s += '='.repeat(4 - (s.length % 4));
	return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export async function verifyIdToken(idToken, expectedClientId, provider) {
	const [h, p, s] = idToken.split('.');
	const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
	const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));

	// Valitse JWKS-URL
	let jwksUrl;
	if (provider === 'google') {
		jwksUrl = 'https://www.googleapis.com/oauth2/v3/certs';
	} else if (provider === 'microsoft') {
		// issuer on muotoa: https://login.microsoftonline.com/{tenant}/v2.0
		const base = (payload.iss || '').replace(/\/v2\.0$/, '');
		jwksUrl = `${base}/discovery/v2.0/keys`;
	} else {
		throw new Error('Unsupported provider for JWKS');
	}

	// Hae JWKS; jos MS-tenantissa ei löydy, fallback /commoniin
	let jwks = await (await fetch(jwksUrl)).json();
	if (provider === 'microsoft' && (!jwks?.keys || !Array.isArray(jwks.keys))) {
		jwks = await (await fetch('https://login.microsoftonline.com/common/discovery/v2.0/keys')).json();
	}

	// Etsi sopiva avain: kid tai x5t
	const jwk = jwks.keys.find((k) => (k.kid === header.kid || k.x5t === header.kid) && (k.alg ? k.alg === 'RS256' : true));
	if (!jwk) throw new Error('JWKS key not found');

	const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
	const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToBytes(s), new TextEncoder().encode(`${h}.${p}`));
	if (!ok) throw new Error('Invalid signature');

	// Issuer/audience tarkistukset provider-kohtaisesti
	const issOk =
		(provider === 'google' && (payload.iss === 'https://accounts.google.com' || payload.iss === 'accounts.google.com')) ||
		(provider === 'microsoft' &&
			typeof payload.iss === 'string' &&
			payload.iss.startsWith('https://login.microsoftonline.com/') &&
			payload.iss.endsWith('/v2.0'));
	if (!issOk) throw new Error('bad iss');

	if (!(payload.aud === expectedClientId || payload.azp === expectedClientId)) throw new Error('bad aud');
	if (payload.exp * 1000 < Date.now()) throw new Error('expired');

	return payload; // sub, email, (microsoft: oid/tid), jne.
}
