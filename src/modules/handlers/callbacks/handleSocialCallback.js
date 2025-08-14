import { deriveUserIdAlias } from '../../utilities/deriveUserIdAlias.js';
import { verifyIdToken } from '../../utilities/verifyJWKidToken.js';

const PROVIDER_POLICY = {
	google: (claims) => ({
		ok: claims.email_verified === true && typeof claims.email === 'string' /* && claims.hd === 'vorte.app' */,
		email: claims.email || null,
	}),
	microsoft: (claims, tid) => ({
		ok: claims.tid === tid && typeof claims.email === 'string',
		email: claims.email || null,
	}),
	// apple myöhemmin -> ok:false (tai relay-case handling)
};

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
			headers: { 'Set-Cookie': 'AUTHN_VERIFIER=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
			body: 'Request is invalid',
		};
	}

	const getId = CLIENT_IDS[provider];
	const getSecret = CLIENT_SECRETS[provider];
	if (typeof getId !== 'function' || typeof getSecret !== 'function') {
		ctx.waitUntil(env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId));
		return {
			status: 400,
			headers: { 'Set-Cookie': 'AUTHN_VERIFIER=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
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

	if (!tokenRes.ok) {
		const msg = await tokenRes.text();
		ctx.waitUntil(env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId));
		return {
			status: 400,
			headers: { 'Set-Cookie': 'AUTHN_VERIFIER=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
			body: `Token exchange failed: ${msg}, status502`,
		};
	}

	const token = await tokenRes.json();

	const claims = await verifyIdToken(token.id_token, client_id, provider);

	const { ok, email } =
		provider === 'microsoft' ? PROVIDER_POLICY.microsoft(claims, await env.AZURE_TENANT_ID.get()) : PROVIDER_POLICY.google(claims);

	if (!ok || !email) {
		ctx.waitUntil(env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId));
		return {
			status: 400,
			headers: { 'Set-Cookie': 'AUTHN_VERIFIER=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
			body: `Not valid email`,
		};
	}

	const emailAlias = await deriveUserIdAlias('email', email, await env.ALIAS_SECRET.get());

	let user_id = '';
	const kvHit = await env.AUTHN_KV.get(emailAlias);
	if (kvHit) user_id = kvHit;
	const row = await env.AUTHN_D1.prepare(
		`
			SELECT user_id FROM identifiers
			WHERE alias = ?
			`
	)
		.bind(emailAlias)
		.first();
	if (row && row.user_id) user_id = row.user_id;

	if (!user_id) {
		ctx.waitUntil(env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId));
		return {
			status: 400,
			headers: { 'Set-Cookie': 'AUTHN_VERIFIER=;HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;' },
			body: `Alias does not exist, ${emailAlias}, ${kvHit}, ${row}`,
		};
	}

	const encryptedCookie = await env.CRYPTO_SERVICE.encryptPayload(`${user_id};${vorte_server_secret}`);

	ctx.waitUntil(
		Promise.all([
			env.CRYPTO_SALT_KV.delete(decryptedCookie.saltId),
			env.AUTHN_KV.put(user_id, '1'),
			env.AUTHN_KV.put(emailAlias, user_id, { expirationTtl: 2_592_000 }),
		])
	);
	return {
		status: 302,
		headers: [
			['Content-Type', 'application/json'],
			['Location', env.SIGN_IN_REDIRECT_BASE],
			['Set-Cookie', 'AUTHN_VERIFIER=; Path=/; SameSite=lax; HttpOnly; Secure;  Max-Age=0;'],
			['Set-Cookie', `HAS_ACCOUNT=true; Path=/; SameSite=lax; HttpOnly Secure; Max-Age=315360000;`],
			['Set-Cookie', `AUTHORIZATION=${encryptedCookie}; Path=/; SameSite=Lax; HttpOnly; Secure;  Max-Age=86400;`],
		],
		body: null,
	};
}
