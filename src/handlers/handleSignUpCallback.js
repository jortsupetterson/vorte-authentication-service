export async function handleSignUpCallback() {
	try {
		const [userInput, verifier, decryptedCookie] = await Promise.all([
			request.json(),
			env.AUTHN_VERIFIER.get(),
			parseAuthnCookie(cookies.AUTHN_VERIFIER),
		]);

		if (
			(await env.AUTHN_SESSIONS_KV.get(decryptedCookie[4])) === decryptedCookie[1] &&
			Date.now() - Number(decryptedCookie[3]) < 300_000 &&
			decryptedCookie[2] === verifier &&
			decryptedCookie[1] === userInput.code
		) {
			const operation = await env.DATA_SERVICE.createDb(userInput.form, cookies, lang);
			const data = await JSON.parse(operation);
			const [kvRes, authzCookie, headers] = await Promise.all([
				env.AUTHN_SESSIONS_KV.delete(decryptedCookie[4]),
				getEncryptedCookie('AUTHORIZATION', data.result, env, 86400),
				new Headers(),
			]);
			headers.append('Set-Cookie', 'AUTHN_VERIFIER=""; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0;');
			headers.append('Set-Cookie', authzCookie);
			return new Response(null, {
				status: data.status,
				headers: headers,
			});
		}
		await env.AUTHN_SESSIONS_KV.delete(decryptedCookie[4]);

		return {
			body: null,
			init: {
				status: 400,
				headers: {
					'Set-Cookie': 'AUTHN_VERIFIER=""; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0;',
				},
			},
		};
	} catch (err) {
		console.error('[AUTHN] Callback error:', err);
		throw new Error(err);
	}
}
