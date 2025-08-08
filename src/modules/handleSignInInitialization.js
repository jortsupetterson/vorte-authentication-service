import { handleSocialInit } from './handlers/inits/handleSocialInit.js';
import { handleOtcInit } from './handlers/inits/handleOtcInit.js';

//O1 lookups map
const methodsMap = {
	otc: async (env, ctx, lang, cookies, segments) => {
		return await handleOtcInit(env, ctx, lang, cookies, segments);
	},
	totp: '',
	social: async (env, ctx, lang, cookies, segments) => {
		return await handleSocialInit(env, ctx, lang, cookies, segments);
	},
	web_authn: '',
};

export async function handleSignInInitialization(env, ctx, lang, cookies, segments) {
	const handler = await methodsMap[segments[4]];
	return await handler(env, ctx, lang, cookies, segments);
}
