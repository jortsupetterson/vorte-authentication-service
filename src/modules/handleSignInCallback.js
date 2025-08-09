import { handleSocialCallback } from './handlers/callbacks/handleSocialCallback.js';
//O1 lookups map
const methodsMap = {
	otc: async (env, ctx, lang, cookies, segments) => {},
	totp: '',
	social: async (env, ctx, lang, cookies, segments, code, state) => {
		return await handleSocialCallback(env, ctx, lang, cookies, segments, code, state);
	},
	web_authn: '',
};

export async function handleSignInCallback(env, ctx, lang, cookies, segments, code, state) {
	const handler = await methodsMap[segments[4]];
	return await handler(env, ctx, lang, cookies, segments, code, state);
}
