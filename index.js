const q = require('q');
const sha = str => (require('crypto-js/sha3'))(str).toString();

module.exports = (key_id, secret_key, payload, cb) => {
	let deferred = q.defer();
	let salt = Array.apply(null, Array(64)).map(() => (
		'0' + (Math.floor(Math.random() * 256)).toString(16)).substr(-2)
	).join('');
	let time = '' + (new Date()).getTime();
	let hash = sha(secret_key + sha(salt + sha(secret_key + payload + time)));
	deferred.resolve([
		'ss1 keyid=' + key_id,
		'hash=' + hash,
		'salt=' + salt,
		'time=' + time
	].join(', '));
	deferred.promise.nodeify(cb);
	return deferred.promise;
};

module.exports.verify = (header, payload, keyfn, cb) => {
	let deferred = q.defer();
	let h = header.toLowerCase().split(',').map(str => str.trim())
		.reduce((pre, cur) => {
			let key = cur.split('=')[0].replace(/^(authorization: ){0,1}ss1 keyid/, 'keyid');
			let val = cur.split('=')[1];
			pre[key] = val;
			return pre;
		}, {});
	if (Object.keys(h).sort().join(',') !== 'hash,keyid,salt,time') {
		deferred.reject(new Error('Wrong header format.'));
	} else {
		let timeDiff = Math.abs(parseInt(h['time']) - (new Date()).getTime());
		if (timeDiff > 86400000) {
			deferred.reject(new Error('Too big time difference.'));
		} else {
			keyfn(h['keyid'], (err, secret_key) => {
				if (err) return deferred.reject(err);
				if (h['hash'] !== sha(secret_key + sha(h['salt'] + sha(secret_key + payload + h['time'])))) {
					return deferred.reject(new Error('Hash does not match.'));
				}
				deferred.resolve();
			});
		}
	}
	deferred.promise.nodeify(cb);
	return deferred.promise;
};
