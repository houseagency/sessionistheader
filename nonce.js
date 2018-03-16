function generateNonce() {
	return new Array(64).fill(0).map(() => ('0' + (Math.floor(Math.random() * 256).toString(16))).substr(-2)).join('')
}

module.exports = {
	generateNonce
};
