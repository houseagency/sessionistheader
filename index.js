const abConcat = require('array-buffer-concat');
const hex2ab = require('hex-to-array-buffer');
const str2ab = require('encode-utf8');

const jsSHA = require('jssha');
const nonceModule = require('./nonce');

function buffer2ab(buf) {
	const ab = new ArrayBuffer(buf.length);
	const view = new Uint8Array(ab);
	for (var i = 0; i < buf.length; ++i) {
		view[i] = buf[i];
	}
	return ab;
}

function utf8StrToHex(str) {
	var hex;
	try {
		hex = unescape(encodeURIComponent(str))
			.split('').map(function(v){ return v.charCodeAt(0).toString(16); })
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
	.then(function(bodyPayload) {
		hash.update(bodyPayload);
		hash.update(str2ab(date));
		return hash.getHMAC('HEX');
	});
}

function payload_handler(payload) {
	return new Promise(function(resolve, reject) {

		if (typeof payload.byteLength !== 'undefined') {

			resolve(payload);

		} else if (typeof payload === 'string') {
			resolve(str2ab(payload));


		} else if (typeof payload === 'object' && typeof payload.on === 'function') {

			var data = new ArrayBuffer(0);

			payload.on('data', function(chunk) {
				const chunkAb = buffer2ab(chunk);
				data = abConcat(data, chunkAb);
			});
			payload.on('end', function() { resolve(data) });
			payload.on('error', function() { reject(new Error('Error when reading payload events.')); });


		} else {
			reject(new Error('Unknown payload format.'));
		}
	})
}

function generate(key_id, secret_key, method, path, payload, date, cb) {
	// Implement callback:
	if (typeof cb === 'function') {
		generate(key_id, secret_key, method, path, payload, date)
		.then(function(str) { setImmediate(function() { cb(null, str); }); })
		.catch(function(err) { setImmediate(function() { cb(err); }); });
		return;
	}

	payload = payload_handler(payload);

	return new Promise(function(resolve, reject) {
		if (typeof key_id !== 'string') {
			reject(new Error('Key id must be a string.'));
		} else if (typeof secret_key !== 'string') {
			reject(new Error('Secret key must be a string.'));
		} else {
			resolve();
		}
	})
	.then(function() {
		var nonce = nonceModule.generateNonce();
		return hash(secret_key, nonce, method, path, payload, date)
		.then(function(hashStr) {
			return 'ss1 keyid=' + key_id + ', hash=' + hashStr + ', nonce=' + nonce;
		});
	});
}

function verify(headerStr, method, path, payload, date, keyfn, cb) {
	// Implement callback:
	if (typeof cb === 'function') {
		module.exports.verify(headerStr, method, path, payload, date, keyfn)
		.then(function(str) { setImmediate(function() { cb(null, str); }); })
		.catch(function(err) { setImmediate(function() { cb(err); }); });
		return;
	}

	payload = payload_handler(payload);

	return new Promise(function(resolve, reject) {
		if (typeof headerStr !== 'string') {
			reject(new Error('Header must be a string.'));
		} else {
			resolve();
		}
	})
	.then(function() {
		var timestamp = new Date(date).getTime();
		if (typeof(timestamp) !== "number") {
			throw new Error('Date format not valid.');
		} else if (Math.abs(timestamp - (new Date()).getTime()) > 86400000) {
			throw new Error('Too big time difference.');
		}
	})
	.then(function() {
		var header = headerStr
			.replace(/^([^: ]+: ){0,1}ss1 /, '')
			.split(/,\s*/)
			.reduce(function(col, line) {
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
	.then(function(header) {
		return new Promise(function(resolve, reject) {
			setImmediate(function() { keyfn(header['keyid'], function(err, secret_key) {
				if (err) {
					reject(err);
				} else if (!secret_key) {
					reject(new Error('No such key.'));
				} else {
					hash(secret_key, header['nonce'], method, path, payload, date)
					.then(function(hashStr) {
						if (header['hash'] !== hashStr) {
							reject(new Error('Hash does not match.'));
						} else {
							resolve(header['keyid']);
						}
					})
					.catch(function(err) {
						reject(err);
					});
				}
			})});
		});
	});
}

module.exports = generate;
module.exports.verify = verify;
