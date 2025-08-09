const CLIENT_IDS = {
	google: async (env) => await env.GOOGLE_CLIENT_ID.get(),
	microsoft: async (env) => await env.AZURE_CLIENT_ID.get(),
};

const CLIENT_SECRETS = {
	google: async (env) => await env.GOOGLE_CLIENT_SECRET.get(),
	microsoft: async (env) => await env.AZURE_CLIENT_SECRET.get(),
};

export async function handleSocialCallback(env, ctx, lang, cookies, segments, code, stateFromQuery) {
	const [redirectUri, decryptedCookie, vorte_server_secret] = await Promise.all([
		env.SOCIAL_AUTHN_REDIRECT_URI,
		env.CRYPTO_SERVICE.decryptPayload(cookies.AUTHN_CHALLENGE),
		env.VORTE_SERVER_SECRET.get(),
	]);

	if (!decryptedCookie?.plainText) {
		return {
			status: 400,
			headers: { 'Set-Cookie': 'AUTHN_CHALLENGE=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
			body: null,
		};
	}

	// `${method};${provider};${subject};${state};${PKCE.verifier};${date};${vorte_server_secret}`
	const parts = decryptedCookie.plainText.split(';');
	const provider = parts[1];
	const cookieState = parts[3];
	const verifier = parts[4];
	const ts = Number(parts[5]);

	if (!stateFromQuery || stateFromQuery !== cookieState) {
		ctx.waitUntil(env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId));
		return {
			status: 400,
			headers: { 'Set-Cookie': 'AUTHN_CHALLENGE=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
			body: `State From Query !state from cookie,${cookieState}, ${stateFromQuery}, Decrypted cookie plain text: ${
				decryptedCookie.plainText
			}, Entire cookie obj: ${JSON.stringify(cookies)}`,
		};
	}

	const kvChallenge = await env.AUTHN_SESSIONS_KV.get(stateFromQuery);
	const validPkce = kvChallenge ? await env.CRYPTO_SERVICE.verifyProofKeyForCodeExchange(kvChallenge, verifier) : false;
	const notExpired = Date.now() - ts <= 300_000;
	const serverOk = parts[6] === vorte_server_secret;

	if (!validPkce || !notExpired || !serverOk) {
		ctx.waitUntil(env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId));
		return {
			status: 400,
			headers: { 'Set-Cookie': 'AUTHN_CHALLENGE=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
			body: 'Request is invalid',
		};
	}

	const getId = CLIENT_IDS[provider];
	const getSecret = CLIENT_SECRETS[provider];
	if (typeof getId !== 'function' || typeof getSecret !== 'function') {
		ctx.waitUntil(env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId));
		return {
			status: 400,
			headers: { 'Set-Cookie': 'AUTHN_CHALLENGE=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
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

	const tokenURL =
		provider === 'google' ? 'https://oauth2.googleapis.com/token' : 'https://login.microsoftonline.com/common/oauth2/v2.0/token';

	const tokenRes = await fetch(tokenURL, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: params,
	});

	ctx.waitUntil(env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId));

	if (!tokenRes.ok) {
		const msg = await tokenRes.text();
		return {
			status: 502,
			headers: { 'Set-Cookie': 'AUTHN_CHALLENGE=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
			body: `Token exchange failed: ${msg}, status502`,
		};
	}

	return {
		status: tokenRes.status,
		headers: {
			'Content-Type': 'application/json',
			'Set-Cookie': 'AUTHN_CHALLENGE=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;',
		},
		body: JSON.stringify(await tokenRes.json()),
	};
}
