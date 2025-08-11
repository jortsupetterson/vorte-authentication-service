function b64urlToBytes(s) {
	s = s.replace(/-/g, '+').replace(/_/g, '/');
	if (s.length % 4) s += '='.repeat(4 - (s.length % 4));
	return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

const CLIENT_IDS = {
	google: async (env) => await env.GOOGLE_CLIENT_ID.get(),
	microsoft: async (env) => await env.AZURE_CLIENT_ID.get(),
};

const CLIENT_SECRETS = {
	google: async (env) => await env.GOOGLE_CLIENT_SECRET.get(),
	microsoft: async (env) => await env.AZURE_CLIENT_SECRET.get(),
};

const URL_BASES = {
	google: 'https://oauth2.googleapis.com/token',
	microsoft: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
};

export async function handleSocialCallback(env, ctx, lang, cookies, segments, code, stateFromQuery) {
	const [redirectUri, decryptedCookie, vorte_server_secret] = await Promise.all([
		env.SOCIAL_AUTHN_REDIRECT_URI,
		env.CRYPTO_SERVICE.decryptPayload(cookies.AUTHN_VERIFIER),
		env.VORTE_SERVER_SECRET.get(),
	]);

	// `${method};${provider};${subject};${state};${PKCE.verifier};${date};${vorte_server_secret}`
	const parts = decryptedCookie.plainText.split(';');
	const provider = parts[1];
	const cookieState = parts[3];
	const verifier = parts[4];
	const ts = Number(parts[5]);

	const validState = stateFromQuery === cookieState;
	const kvChallenge = await env.AUTHN_SESSIONS_KV.get(stateFromQuery);
	const validPkce = kvChallenge ? await env.CRYPTO_SERVICE.verifyProofKeyForCodeExchange(kvChallenge, verifier) : false;
	const notExpired = Date.now() - ts <= 300_000;
	const serverOk = parts[6] === vorte_server_secret;

	if (!validState || !validPkce || !notExpired || !serverOk) {
		ctx.waitUntil(env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId));
		return {
			status: 400,
			headers: { 'Set-Cookie': 'AUTHN_VERIFIER=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
			body: 'Request is invalid',
		};
	}

	const getId = CLIENT_IDS[provider];
	const getSecret = CLIENT_SECRETS[provider];
	if (typeof getId !== 'function' || typeof getSecret !== 'function') {
		ctx.waitUntil(env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId));
		return {
			status: 400,
			headers: { 'Set-Cookie': 'AUTHN_VERIFIER=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
			body: 'Unsupported provider',
		};
	}

	const client_id = await getId(env);
	const client_secret = await getSecret(env);

	const params = new URLSearchParams({
		code,
		client_id,
		client_secret,
		redirect_uri: redirectUri,
		grant_type: 'authorization_code',
		code_verifier: verifier,
	});

	const tokenRes = await fetch(URL_BASES[provider], {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: params,
	});

	ctx.waitUntil(env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId));

	if (!tokenRes.ok) {
		const msg = await tokenRes.text();
		return {
			status: 502,
			headers: { 'Set-Cookie': 'AUTHN_VERIFIER=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
			body: `Token exchange failed: ${msg}, status502`,
		};
	}

	const token = await tokenRes.json();

	const [hdrB64, payloadB64] = token.id_token.split('.');
	const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(payloadB64)));

	return {
		status: tokenRes.status,
		headers: {
			'Content-Type': 'application/json',
			'Set-Cookie': 'AUTHN_VERIFIER=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;',
		},
		body: JSON.stringify(JSON.stringify(payload)),
	};
}
