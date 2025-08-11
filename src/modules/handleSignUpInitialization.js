import { sendEmail } from './utilities/mail-client.js';

export async function handleSignUpInitialization(env, ctx, lang, form) {
	try {
		const code = new Promise((resolve) => {
			const digits = env.CRYPTO_SERVICE.getEightDigits();
			resolve(digits);
		});

		const [res, state, PKCE, vorte_server_secret] = await Promise.all([
			sendEmail(
				env,
				[form.email],
				{
					subject: {
						fi: 'Olet luomassa tiliä palveluun Vorte',
						sv: 'Du håller på att skapa ett konto i Vorte',
						en: 'You are creating an account in Vorte',
					}[lang],
					plainText: {
						fi: `
Hei ${form.firstname} ${form.lastname}!

Olemme vastaanottaneet pyyntösi luoda käyttäjätili Vorteen sähköpostille: "${form.email}"

Jos et yrittänyt luoda tiliä, voit jättää viestin huomiotta.

Vahvistathan, että kyseessä on todella sinä – kertakäyttökoodi on voimassa 5 minuuttia.

Kertakäyttökoodisi: ${await code}

Parhain terveisin
Vorten tiimi
`,
						sv: `
Hej ${form.firstname} ${form.lastname}!

Vi har mottagit din begäran om att skapa ett Vorte-konto med e-postadressen: "${form.email}"

Om du inte försökte skapa ett konto kan du bara ignorera detta meddelande.

Bekräfta att det verkligen är du – engångskoden är giltig i 5 minuter.

Din engångskod: ${await code}

Vänliga hälsningar
Vorte-teamet
`,
						en: `
Hi ${form.firstname} ${form.lastname}!

We have received your request to create a Vorte account with the email: "${form.email}"

If you did not try to create an account, you can safely ignore this message.

Please confirm it was really you – the one-time code is valid for 5 minutes.

Your one-time code: ${await code}

Best regards
The Vorte team
`,
					}[lang],
				},
				false,
				false,
				false
			),
			env.CRYPTO_SERVICE.getCryptographicState(),
			env.CRYPTO_SERVICE.getProofKeyForCodeExchange(),
			env.VORTE_SERVER_SECRET.get(),
		]);

		//`${method};${provider};${subject};${state};${PKCE.verifier};${date};${vorte_server_secret}`
		const encryptedCookie = await env.CRYPTO_SERVICE.encryptPayload(
			`otc;email;${form.email};${state};${PKCE.verifier};${Date.now()};${vorte_server_secret}`
		);

		ctx.waitUntil(env.AUTHN_SESSIONS_KV.put(state, `${PKCE.challenge};${await code}`, { expirationTtl: 300 }));

		return {
			status: 202,
			headers: {
				'Set-Cookie': `AUTHN_VERIFIER=${encryptedCookie}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300;`,
			},
			body: null,
		};
	} catch (err) {
		console.error('initializeAuth error:', err);
		return {
			status: 400,
			headers: {
				'Set-Cookie': `AUTHN_VERIFIER=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0;`,
			},
			body: JSON.stringify(err),
		};
	}
}
