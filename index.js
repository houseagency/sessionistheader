const q = require('q');
const jssha = require('jssha');
const _ = require('lodash');

function hash(secret_key, nonce, payload, time) {
	let hash1 = new jssha('SHA3-512', 'TEXT');
	let hash2 = new jssha('SHA3-512', 'TEXT');
	let hash3 = new jssha('SHA3-512', 'TEXT');

	return q.fcall(() => {
		hash1.update(secret_key);
		hash2.update(nonce);
		hash3.update(secret_key);
	})
	.then(() => {

		let deferred = q.defer();

		if (typeof payload === 'string') {
			hash1.update(payload);
			deferred.resolve();
		} else {
			deferred.reject(new Error('Unknown payload format.'));
		}

		return deferred.promise;
	})
	.then(() => {
		hash2.update(_.toString(time));
		hash2.update(hash1.getHash('HEX'));
		hash3.update(hash2.getHash('HEX'));
		return hash3.getHash('HEX');
	});
}

module.exports = (key_id, secret_key, payload, timestamp, cb) => {
	// Timestamp is optional:
	if (typeof timestamp === 'function') {
		cb = timestamp;
		timestamp = 0;
	}

	// Implement callback:
	if (typeof cb === 'function') {
		module.exports(key_id, secret_key, payload, timestamp)
		.then(str => setImmediate(() => cb(null, str)))
		.catch(err => setImmediate(() => cb(err)));
		return;
	}

	return q.fcall(() => {
		if (typeof key_id !== 'string') throw new Error('Key id must be a string.');
		if (typeof secret_key !== 'string') throw new Error('Secret key must be a string.');
	})
	.then(() => {
		// Use current time if none (or 0) was sent to us:
		let time = _.toInteger(timestamp);
		if (time === 0) time = _.now();
		return time;
	})
	.then(time => {
		let nonce = new Array(64).fill(0).map(() => ('0' + (Math.floor(Math.random() * 256).toString(16))).substr(-2)).join('');
		return hash(secret_key, nonce, payload, time)
		.then(hashStr => {
			return 'ss1 keyid=' + key_id + ', hash=' + hashStr + ', nonce=' + nonce + ', time=' + time;
		});
	});
};

module.exports.verify = (headerStr, payload, keyfn, cb) => {
	if (typeof headerStr !== 'string') return cb(new Error('Header must be a string.'));

	let deferred = q.defer();
	let header = headerStr.replace(/^([^: ]+: ){0,1}ss1 /, '').split(/,\s*/)
		.reduce((pre, cur) => Object.assign({}, pre, _.fromPairs([ cur.split('=') ])), {});
	if (Object.keys(header).sort().join(',') !== 'hash,keyid,nonce,time') {
		deferred.reject(new Error('Wrong header format.'));
	} else if (Math.abs(header['time'] - _.now()) > 86400000) {
		deferred.reject(new Error('Too big time difference.'));
	} else {
		setImmediate(() => keyfn(header['keyid'], (err, secret_key) => {
			if (err) return deferred.reject(err);
			hash(secret_key, header['nonce'], payload, header['time'])
			.then(hashStr => {
				if (header['hash'] !== hashStr) {
					return deferred.reject(new Error('Hash does not match.'));
				}
				deferred.resolve();
			});
		}));
	}
	deferred.promise.nodeify(cb);
	return deferred.promise;
};
