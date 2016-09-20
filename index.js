const cryptojs = require('crypto-js');
const q = require('q');
const _ = require('lodash');

const sha = str => cryptojs.SHA3(str).toString();

module.exports = (key_id, secret_key, payload, cb) => {
	let deferred = q.defer();
	let nonce = cryptojs.lib.WordArray.random(64).toString();
	let time = _.now();
	let hash = sha(secret_key + sha(nonce + sha(secret_key + payload + time)));
	deferred.resolve('ss1 keyid=' + key_id + ', hash=' + hash + ', nonce=' + nonce + ', time=' + time);
	deferred.promise.nodeify(cb);
	return deferred.promise;
};

module.exports.verify = (headerStr, payload, keyfn, cb) => {
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
			if (header['hash'] !== sha(secret_key + sha(header['nonce'] + sha(secret_key + payload + header['time']))))
				return deferred.reject(new Error('Hash does not match.'));
			deferred.resolve();
		}));
	}
	deferred.promise.nodeify(cb);
	return deferred.promise;
};
