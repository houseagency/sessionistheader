const q = require('q');
const jssha = require('jssha');
const _ = require('lodash');

const hash = (secret_key, nonce, method, path, payload, date) => {
	let hash = new jssha('SHA-512', 'ARRAYBUFFER');
	hash.setHMACKey(secret_key, 'TEXT');

	hash.update(new Buffer(nonce, "hex"));
	hash.update(new Buffer(method));
	hash.update(new Buffer(path));

	return payload
	.then(bodyPayload => {
		hash.update(bodyPayload);
		hash.update(date);
		return hash.getHMAC('HEX');
	});
}

const payload_handler = (payload) => {
	let deferred = q.defer();

	if (typeof payload === 'string') {
		deferred.resolve(new Buffer(payload));

	} else if (typeof payload === 'object' && typeof payload.on === 'function') {

		let data = new Buffer('');

		payload.on('data', chunk => data = Buffer.concat([data, chunk]));
		payload.on('end', () => deferred.resolve(data));
		payload.on('error', () => deferred.reject(new Error('Error when reading payload events.')));

	} else {
		deferred.reject(new Error('Unknown payload format.'));
	}

	return deferred.promise;
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

	return q.fcall(() => {
		if (typeof key_id !== 'string') throw new Error('Key id must be a string.');
		if (typeof secret_key !== 'string') throw new Error('Secret key must be a string.');
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

	return q.fcall(() => {
		if (typeof headerStr !== 'string') throw new Error('Header must be a string.');
	})
	.then(() => {
		let timestamp = new Date(date).getTime();
		if (!_.isInteger(timestamp)) {
			throw new Error('Date format not valid.');
		} else if (Math.abs(timestamp - _.now()) > 86400000) {
			throw new Error('Too big time difference.');
		}
	})
	.then(() => {
		let header = headerStr
			.replace(/^([^: ]+: ){0,1}ss1 /, '')
			.split(/,\s*/)
			.reduce((pre, cur) => Object.assign({}, pre, _.fromPairs([ cur.split('=') ])), {});
		if (Object.keys(header).sort().join(',') !== 'hash,keyid,nonce') {
			throw new Error('Wrong header format.');
		}
		return header;
	})
	.then(header => {
		let deferred = q.defer();
		setImmediate(() => keyfn(header['keyid'], (err, secret_key) => {
			if (err) return deferred.reject(err);
			hash(secret_key, header['nonce'], method, path, payload, date)
			.then(hashStr => {
				if (header['hash'] !== hashStr) {
					return deferred.reject(new Error('Hash does not match.'));
				}
				deferred.resolve();
			})
			.catch(err => {
				deferred.reject(err);
			});
		}));
		return deferred.promise;
	});
}

module.exports = generate;
module.exports.verify = verify;
