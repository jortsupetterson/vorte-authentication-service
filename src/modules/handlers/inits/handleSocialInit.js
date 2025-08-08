const CLIENT_IDS = {
	google: async (env) => {
		return await env.GOOGLE_CLIENT_ID.get();
	},
	microsoft: async (env) => {
		return await env.MICROSOFT_CLIENT_ID.get();
	},
};

export async function handleSocialInit(env, ctx, lang, cookies, segments) {
	const [clientId, redirectUri, PKCE, state, vorte_server_secret, date] = await Promise.all([
		CLIENT_IDS[segments[5]](env),
		env.SOCIAL_AUTHN_REDIRECT_URI,
		env.CRYPTO_SERVICE.getProofKeyForCodeExchange(),
		env.CRYPTO_SERVICE.getCryptographicState(),
		env.VORTE_SERVER_SECRET.get(),
		Date.now(),
	]);

	//`${method};${provider};${subject};${state};${PKCE.verifier};${date};${vorte_server_secret}`
	const encryptedCookie = await env.CRYPTO_SERVICE.encryptPayload(
		`${segments[4]};${segments[5]};${'unknown'};${state};${PKCE.verifier};${date};${vorte_server_secret}`
	);

	ctx.waitUntil(env.AUTHN_SESSIONS_KV.put(state, PKCE.challenge));

	return {
		status: 302,
		headers: {
			Location: `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=openid email profile&code_challenge=${PKCE.challenge}&code_challenge_method=S256&state${state}`,
			'Set-Cookie': `AUTHN_CHALLENGE=${encryptedCookie};HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300;`,
		},
		body: null,
	};
}
