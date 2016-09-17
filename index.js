const q = require('q');
const cryptojs = require('crypto-js');

const sha = str => cryptojs.SHA3(str).toString();

module.exports = (key_id, secret_key, payload, cb) => {
	let deferred = q.defer();
	let salt = cryptojs.lib.WordArray.random(64).toString();
	let time = '' + (new Date()).getTime();
	let hash = sha(secret_key + sha(salt + sha(secret_key + payload + time)));
	deferred.resolve('ss1 keyid=' + key_id + ', hash=' + hash + ', salt=' + salt + ', time=' + time);
	deferred.promise.nodeify(cb);
	return deferred.promise;
};

module.exports.verify = (header, payload, keyfn, cb) => {
	let deferred = q.defer();
	let h = header.toLowerCase().split(',').map(str => str.trim())
		.reduce((pre, cur) => {
			let [key, val] = cur.replace(/^([^: ]+: ){0,1}ss1 /, '').split('=');
			pre[key] = val;
			return pre;
		}, {});
	if (Object.keys(h).sort().join(',') !== 'hash,keyid,salt,time') {
		deferred.reject(new Error('Wrong header format.'));
	} else {
		if (Math.abs(parseInt(h['time']) - (new Date()).getTime()) > 86400000) {
			deferred.reject(new Error('Too big time difference.'));
		} else {
			setImmediate(() => keyfn(h['keyid'], (err, secret_key) => {
				if (err) return deferred.reject(err);
				if (h['hash'] !== sha(secret_key + sha(h['salt'] + sha(secret_key + payload + h['time']))))
					return deferred.reject(new Error('Hash does not match.'));
				deferred.resolve();
			}));
		}
	}
	deferred.promise.nodeify(cb);
	return deferred.promise;
};
