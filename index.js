const q = require('q');
const jssha = require('jssha');
const _ = require('lodash');

function hash(secret_key, nonce, payload, time) {
	let hash1 = new jssha('SHA3-512', 'TEXT');
	let hash2 = new jssha('SHA3-512', 'TEXT');
	let hash3 = new jssha('SHA3-512', 'TEXT');
	hash1.update(secret_key);
	hash2.update(nonce);
	hash3.update(secret_key);

	hash1.update(payload);

	hash1.update(_.toString(time));
	hash2.update(hash1.getHash('HEX'));
	hash3.update(hash2.getHash('HEX'));
	return hash3.getHash('HEX');
}

module.exports = (key_id, secret_key, payload, timestamp, cb) => {
	if (typeof key_id !== 'string') return cb(new Error('Key id must be a string.'));
	if (typeof secret_key !== 'string') return cb(new Error('Secret key must be a string.'));

	// Timestamp is optional:
	if (typeof timestamp === 'function') {
		cb = timestamp;
	}

	let deferred = q.defer();

	// Use current time if none (or 0) was sent to us:
	let time = _.toInteger(timestamp);
	if (time === 0) time = _.now();

	let nonce = new Array(64).fill(0).map(() => ('0' + (Math.floor(Math.random() * 256).toString(16))).substr(-2)).join('');

	deferred.resolve('ss1 keyid=' + key_id + ', hash=' + hash(secret_key, nonce, payload, time) + ', nonce=' + nonce + ', time=' + time);
	deferred.promise.nodeify(cb);
	return deferred.promise;
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
			if (header['hash'] !== hash(secret_key, header['nonce'], payload, header['time']))
				return deferred.reject(new Error('Hash does not match.'));
			deferred.resolve();
		}));
	}
	deferred.promise.nodeify(cb);
	return deferred.promise;
};
