import WorkerEntrypoint from 'cloudflare:workers';
import { handleAuthenticationInitialization } from './handlers/handleAuthenticationInitialization.js';
import { handleAuthenticationCallback } from './handlers/handleAuthenticationCallback.js';
import { handleSignUpInitialization } from './handlers/handleSignUpInitialization.js';
import { handleSignUpCallback } from './handlers/handleSignUpCallback.js';

export class VorteAuthenticationService extends WorkerEntrypoint {
	async authenticationInitialization() {
		return await handleAuthenticationInitialization();
	}
	async authenticationCallback() {
		return await handleAuthenticationCallback();
	}

	async signUpInitialization() {
		return await handleSignUpInitialization();
	}

	async signUpCallback() {
		return await handleSignUpCallback();
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
