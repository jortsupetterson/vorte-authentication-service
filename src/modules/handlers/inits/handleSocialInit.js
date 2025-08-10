const CLIENT_IDS = {
	google: async (env) => {
		return await env.GOOGLE_CLIENT_ID.get();
	},
	microsoft: async (env) => {
		return await env.AZURE_CLIENT_ID.get();
	},
};
const URL_BASES = {
	google: 'https://accounts.google.com/o/oauth2/v2/auth',
	microsoft: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
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

	ctx.waitUntil(env.AUTHN_SESSIONS_KV.put(state, PKCE.challenge, { expirationTtl: 300 }));

	return {
		status: 302,
		headers: {
			Location: `${
				URL_BASES[segments[5]]
			}?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=openid+email+profile&code_challenge=${
				PKCE.challenge
			}&code_challenge_method=S256&state=${state}`,
			'Set-Cookie': `AUTHN_VERIFIER=${encryptedCookie};HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300;`,
		},
		body: null,
	};
}
