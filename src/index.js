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

	async signUpInitialization(lang, form) {
		return await handleSignUpInitialization(this.env, this.ctx, lang, form);
	}

	async signUpCallback(lang, cookies, form) {
		return await handleSignUpCallback(this.env, this.ctx, lang, cookies, form);
	}
}

export default {
	async fetch(request, env, ctx) {
		const cached = caches.default.match(request);
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
