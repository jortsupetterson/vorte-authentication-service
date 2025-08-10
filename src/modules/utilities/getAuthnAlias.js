/**
 * Rakentaa deterministisen tunnisteen kolmesta osasta SHA-256 -tiivisteenä.
 *
 * @param {string} method
 * @param {string} subject
 * @param {string} salt
 * @returns {Promise<string>} 64-merkkiä pitkä heksadesimaalinen merkkijono
 */
export async function getAuthnAlias(method, email, salt) {
	const str = `${method}|${email}|${salt}`;
	const data = new TextEncoder().encode(str);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Käyttö:
// const id = await makeDeterministicId('user123', 'order456', '2025-07-14');
// console.log(id); // aina sama tulos samoilla osilla
