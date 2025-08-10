async function verifyGoogleIdToken(idToken, expectedClientId) {
	const [h, p, s] = idToken.split('.');
	const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
	const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));

	// hae JWKS ja valitse oikea avain
	const jwks = await (await fetch('https://www.googleapis.com/oauth2/v3/certs')).json();
	const jwk = jwks.keys.find((k) => k.kid === header.kid && k.alg === 'RS256');
	if (!jwk) throw new Error('JWKS key not found');

	const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
	const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToBytes(s), new TextEncoder().encode(`${h}.${p}`));
	if (!ok) throw new Error('Invalid signature');

	// perusclaimit
	if (!['https://accounts.google.com', 'accounts.google.com'].includes(payload.iss)) throw new Error('bad iss');
	if (!(payload.aud === expectedClientId || payload.azp === expectedClientId)) throw new Error('bad aud');
	if (payload.exp * 1000 < Date.now()) throw new Error('expired');

	return payload; // sisältää sub, email, hd, jne.
}

// käyttö:
const claims = await verifyGoogleIdToken(id_token, GOOGLE_CLIENT_ID);
const sub = claims.sub; // <-- käytä tätä alias-hakemiseen
const iss = claims.iss;
