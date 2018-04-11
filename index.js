const abConcat = require('array-buffer-concat');
const hex2ab = require('hex-to-array-buffer');
const str2ab = require('encode-utf8');
const buffer2ab = require('buffer-to-arraybuffer');

const jsSHA = require('jssha');
const nonceModule = require('./nonce');

function utf8StrToHex(str) {
	let hex;
	try {
		hex = unescape(encodeURIComponent(str))
			.split('').map((v) => v.charCodeAt(0).toString(16))
			.join('');
	} catch (err) {
		throw new Error('Invalid input.');
	}
	return hex;
}

function hash(secret_key, nonce, method, path, payload, date) {
	const hash = new jsSHA('SHA-512', 'ARRAYBUFFER');
	hash.setHMACKey(secret_key, 'TEXT');
	hash.update(hex2ab(nonce));
	hash.update(str2ab(method));
	hash.update(str2ab(path));

	return payload
	.then(bodyPayload => {
		hash.update(bodyPayload);
		hash.update(str2ab(date));
		return hash.getHMAC('HEX');
	});
}

function payload_handler(payload) {
	return new Promise((resolve, reject) => {

		if (typeof payload.byteLength !== 'undefined') {

			resolve(payload);

		} else if (typeof payload === 'string') {
			resolve(str2ab(payload));


		} else if (typeof payload === 'object' && typeof payload.on === 'function') {

			let data = new ArrayBuffer(0);

			payload.on('data', chunk => {
				const chunkAb = buffer2ab(chunk);
				data = abConcat(data, chunkAb);
			});
			payload.on('end', () => resolve(data));
			payload.on('error', () => reject(new Error('Error when reading payload events.')));


		} else {
			reject(new Error('Unknown payload format.'));
		}
	})
}

function generate(key_id, secret_key, method, path, payload, date, cb) {
	// Implement callback:
	if (typeof cb === 'function') {
		generate(key_id, secret_key, method, path, payload, date)
		.then(str => setImmediate(() => cb(null, str)))
		.catch(err => setImmediate(() => cb(err)));
		return;
	}

	payload = payload_handler(payload);

	return new Promise((resolve, reject) => {
		if (typeof key_id !== 'string') {
			reject(new Error('Key id must be a string.'));
		} else if (typeof secret_key !== 'string') {
			reject(new Error('Secret key must be a string.'));
		} else {
			resolve();
		}
	})
	.then(() => {
		let nonce = nonceModule.generateNonce();
		return hash(secret_key, nonce, method, path, payload, date)
		.then(hashStr => {
			return 'ss1 keyid=' + key_id + ', hash=' + hashStr + ', nonce=' + nonce;
		});
	});
}

function verify(headerStr, method, path, payload, date, keyfn, cb) {
	// Implement callback:
	if (typeof cb === 'function') {
		module.exports.verify(headerStr, method, path, payload, date, keyfn)
		.then(str => setImmediate(() => cb(null, str)))
		.catch(err => setImmediate(() => cb(err)));
		return;
	}

	payload = payload_handler(payload);

	return new Promise((resolve, reject) => {
		if (typeof headerStr !== 'string') {
			reject(new Error('Header must be a string.'));
		} else {
			resolve();
		}
	})
	.then(() => {
		let timestamp = new Date(date).getTime();
		if (typeof(timestamp) !== "number") {
			throw new Error('Date format not valid.');
		} else if (Math.abs(timestamp - (new Date()).getTime()) > 86400000) {
			throw new Error('Too big time difference.');
		}
	})
	.then(() => {
		let header = headerStr
			.replace(/^([^: ]+: ){0,1}ss1 /, '')
			.split(/,\s*/)
			.reduce((col, line) => {
				const pair = line.split('=');
				const prop = {};

				prop[pair[0]] = pair[1];

				return Object.assign(
					{},
					col,
					prop
				);
			}, {});

		if (Object.keys(header).sort().join(',') !== 'hash,keyid,nonce') {
			throw new Error('Wrong header format.');
		}
		return header;
	})
	.then(header => {
		return new Promise((resolve, reject) => {
			setImmediate(() => keyfn(header['keyid'], (err, secret_key) => {
				if (err) {
					reject(err);
				} else if (!secret_key) {
					reject(new Error('No such key.'));
				} else {
					hash(secret_key, header['nonce'], method, path, payload, date)
					.then(hashStr => {
						if (header['hash'] !== hashStr) {
							reject(new Error('Hash does not match.'));
						} else {
							resolve(header['keyid']);
						}
					})
					.catch(err => {
						reject(err);
					});
				}
			}));
		});
	});
}

module.exports = generate;
module.exports.verify = verify;
