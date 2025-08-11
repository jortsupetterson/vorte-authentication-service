export async function handleSignUpCallback(env, ctx, lang, cookies, message) {
	try {
		const [decryptedCookie, vorte_server_secret] = await Promise.all([
			env.CRYPTO_SERVICE.decryptPayload(cookies.AUTHN_VERIFIER),
			env.VORTE_SERVER_SECRET.get(),
		]);

		// `${method};${provider};${subject};${state};${PKCE.verifier};${date};${vorte_server_secret}`
		const parts = decryptedCookie.plainText.split(';');
		const cookieState = parts[3];
		const pkceVerifier = parts[4];
		const ts = Number(parts[5]);

		const kvRaw = await env.AUTHN_SESSIONS_KV.get(cookieState);
		const kvSplit = kvRaw.split(';');
		const pkceChallenge = kvSplit[0];

		const notExpired = Date.now() - ts <= 300_000;
		const serverOk = parts[6] === vorte_server_secret;
		const validPkce = await env.CRYPTO_SERVICE.verifyProofKeyForCodeExchange(pkceChallenge, pkceVerifier);
		const validCode = message.code === kvSplit[1];

		if (!notExpired || !serverOk || !validPkce || !validCode) {
			ctx.waitUntil(async () => {
				env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId);
				env.AUTHN_SESSIONS_KV.delete(cookieState);
			});
			return {
				status: 400,
				headers: { 'Set-Cookie': 'AUTHN_VERIFIER=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
				body: 'Request is invalid',
			};
		}

		const result = await env.DATA_SERVICE.createDb(message.form, cookies, lang);
		const encryptedCookie = await env.CRYPTO_SERVICE.encryptPayload(result.body);

		ctx.waitUntil(async () => {
			env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId);
			env.AUTHN_SESSIONS_KV.delete(cookieState);
		});

		return {
			status: result.status,
			headers: [
				['Set-Cookie', 'AUTHN_VERIFIER=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0;'],
				[('Set-Cookie', `AUTHORIZATION=${encryptedCookie}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400;`)],
			],
			body: null,
		};
	} catch (err) {
		return {
			status: 400,
			headers: [['Set-Cookie', 'AUTHN_VERIFIER=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0;']],
			body: JSON.stringify(err),
		};
	}
}
