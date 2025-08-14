import { WorkerEntrypoint } from 'cloudflare:workers';
import { handleSignInInitialization } from './modules/handleSignInInitialization.js';
import { handleSignInCallback } from './modules/handleSignInCallback.js';
import { handleSignUpInitialization } from './modules/handleSignUpInitialization.js';
import { handleSignUpCallback } from './modules/handleSignUpCallback.js';

export class VorteAuthenticationService extends WorkerEntrypoint {
	async signInInitialization(lang, cookies, segments) {
		return await handleSignInInitialization(this.env, this.ctx, lang, cookies, segments);
	}
	async signInCallback(lang, cookies, segments, code, state) {
		return await handleSignInCallback(this.env, this.ctx, lang, cookies, segments, code, state);
	}

	async signUpInitialization(lang, message) {
		return await handleSignUpInitialization(this.env, this.ctx, lang, message);
	}

	async signUpCallback(lang, cookies, message) {
		return await handleSignUpCallback(this.env, this.ctx, lang, cookies, message);
	}

	async verifyBearer(authorizationCookie) {
		const [cookieStr, secretStr] = await Promise.all([
			this.env.CRYPTO_SERVICE.decryptPayload(authorizationCookie),
			this.env.VORTE_SERVER_SECRET.get(),
		]);
		const [id, issuer] = cookieStr.plainText.split(';', 2);
		const [validBearer, validIssuer] = await Promise.all([
			this.env.AUTHN_KV.get(id).then((v) => v === '1'),
			Promise.resolve(secretStr === issuer),
		]);
		return validBearer && validIssuer ? id : undefined;
	}
}

export default {
	async fetch(request, env, ctx) {
		const cached = await caches.default.match(request);
		if (cached) return cached;
		const response = new Response(null, {
			status: 404,
			headers: {
				'cache-control': 'public, max-age=31536000, immutable',
			},
		});
		ctx.waitUntil(caches.default.put(request, response.clone()));
		return response;
	},
};
