const crypto = require('crypto');

const hash = (secret_key, nonce, method, path, payload, date) => {
	let hash = crypto.createHmac('sha512', secret_key);

	hash.update(new Buffer(nonce, 'hex'));
	hash.update(new Buffer(method));
	hash.update(new Buffer(path));

	return payload
	.then(bodyPayload => {
		if (bodyPayload.length) hash.update(bodyPayload);
		hash.update(date);
		return hash.digest('hex');
	});
}

const payload_handler = (payload) => {
	return new Promise((resolve, reject) => {
		if (typeof payload === 'string') {
			resolve(new Buffer(payload));

		} else if (typeof payload === 'object' && typeof payload.on === 'function') {

			let data = new Buffer('');

			payload.on('data', chunk => data = Buffer.concat([data, chunk]));
			payload.on('end', () => resolve(data));
			payload.on('error', () => reject(new Error('Error when reading payload events.')));

		} else {
			reject(new Error('Unknown payload format.'));
		}
	})
}

const generate = (key_id, secret_key, method, path, payload, date, cb) => {
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
		let nonce = new Array(64).fill(0).map(() => ('0' + (Math.floor(Math.random() * 256).toString(16))).substr(-2)).join('');
		return hash(secret_key, nonce, method, path, payload, date)
		.then(hashStr => {
			return 'ss1 keyid=' + key_id + ', hash=' + hashStr + ', nonce=' + nonce;
		});
	});
}

const verify = (headerStr, method, path, payload, date, keyfn, cb) => {
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
