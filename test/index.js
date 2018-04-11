const expect = require('chai').expect;
const header = require('../index');
const nonce = require('../nonce');
const os = require('os');
const fs = require('fs');

const td = require('testdouble');

describe('Module', () => {

	let today = (new Date()).toUTCString();
	let yesturday = (new Date((new Date()).getTime() - (25 * 60 * 60 * 1000))).toUTCString();

	describe('creating header', () => {

		it('should provide a callback interface', done => {
			header('my key id', 'my secret key', 'POST', '/endpoint', 'the payload', today, (err, data) => {
				done();
			});
		});

		it('should provide a promise interface', done => {
			header('my key id', 'my secret key', 'POST', '/endpoint', 'the payload', today)
			.then(data => {
				done();
			});
		});

		it('should return a string', done => {
			header('my key id', 'my secret key', 'POST', '/endpoint', 'the payload', today)
			.then(data => {
				expect(data).to.be.a('string');
			})
			.then(done);
		});

		it('should return a string starting with our scheme identifyer', done => {
			header('my key id', 'my secret key', 'POST', '/endpoint', 'the payload', today)
			.then(data => {
				expect(data.substr(0, 4)).to.equal('ss1 ');
			})
			.then(done);
		});

		it('should return a string with proper length', done => {
			header('my key id', 'my secret key', 'POST', '/endpoint', 'the payload', today)
			.then(data => {
				expect(data.length).to.equal(290);
			})
			.then(done);
		});

		describe('with a fixed nonce', done => {

			beforeEach(() => {
				td.replace(nonce, 'generateNonce');
				td.when(nonce.generateNonce()).thenReturn(
					new Array(128).fill('0').join('')
				);
			});

			it('should return the same header every time', done => {
				header(
					'my key id',
					'my secret key',
					'POST',
					'/endpoint',
					'the payload', 
					new Date(1318023197289).toUTCString()
				)
				.then(data => {
					expect(data).to.equal('ss1 keyid=my key id, hash=15622b52c1a45de70bca5102c7af5006cc64008a8e71aaf787361391fcf534590e99b4a19aa305ee32c9ab28661c99ffd33683a13b8c0f6ff7236f6030f86d6f, nonce=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000');
				})
				.then(done);

			});

			afterEach(() => {
				td.reset();
			});

		});

		describe('with another fixed nonce', done => {

			beforeEach(() => {
				td.replace(nonce, 'generateNonce');
				td.when(nonce.generateNonce()).thenReturn(
					'73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a804973475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049'
				);
			});

			it('should return the same header every time', done => {
				header(
					'my key id',
					'my secret key',
					'POST',
					'/endpoint',
					'the payload', 
					new Date(1318023197289).toUTCString()
				)
				.then(data => {
					expect(data).to.equal('ss1 keyid=my key id, hash=5ccb276c2f40e9c7bd95077ef5ff56f68e3ea30146bce4ee76cf443cf67f2f7d33546d4fe18d0f2a93bd8d353d7a45062baf6c4a8cffa0b95b90cb98aca9f379, nonce=73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a804973475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049');
				})
				.then(done);

			});

			it('should return the same string on stream payload, buffer payload and string payload', done => {

				const keyid = 'some key id';
				const secretkey = 'blarf';
				const method = 'POST';
				const endpoint = '/example';
				const date = new Date().toUTCString();

				const payloadStr = '{ "hello": "this is a test" }';
				const payloadBuffer = Buffer.from(payloadStr);
				const payloadFile = os.tmpdir() + '/payload.tmp';

				fs.writeFileSync(payloadFile, payloadBuffer);

				header(keyid, secretkey, method, endpoint, payloadStr, date)
					.then(headerStr => {

						header(
							keyid,
							secretkey,
							method,
							endpoint,
							payloadBuffer,
							date
						)
							.then(headerBuffer => {

								header(
									keyid,
									secretkey,
									method,
									endpoint,
									fs.createReadStream(payloadFile),
									date
								)
									.then(headerStream => {


										expect(headerStream).to.equal(headerStr);
										expect(headerBuffer).to.equal(headerStr);

										done();

									});

							});

					});


			});

			afterEach(() => {
				td.reset();
			});

		});

	});

	describe('verifying header', () => {

		it('should provide a callback interface', done => {
			header.verify('the header str', 'POST', '/endpoint', 'the payload', today, (keyid, cb) => { cb(null, 'the secret key'); }, (err, data) => {
				done();
			});
		});

		it('should provide a promise interface', done => {
			header.verify('the header str', 'POST', '/endpoint', 'the payload', today, (keyid, cb) => { cb(null, 'the secret key'); })
			.then(data => {
				done();
			})
			.catch(err => {
				done();
			});
		});

		it('should be able to verify headers created by the module', done => {
			header('my key id', 'my secret key', 'POST', '/endpoint', 'the payload', today)
			.then(data => {
				return header.verify(data, 'POST', '/endpoint', 'the payload', today, (keyid, cb) => { cb(null, 'my secret key'); });
			})
			.then(keyid => {
				expect(keyid).to.equal('my key id');
				done();
			})
			.catch(err => {
				done(err);
			});
		});

		it('should fail when secret key is not the same', done => {
			header('my key id', 'my secret key', 'POST', '/endpoint', 'the payload', today)
			.then(data => {
				return header.verify(data, 'POST', '/endpoint', 'the payload', today, (keyid, cb) => { cb(null, 'another secret key'); });
			})
			.then(() => {
				done(new Error('Should not get here.'));
			})
			.catch(err => {
				expect(err.message).to.equal('Hash does not match.');
				done();
			})
			.catch(err => {
				done(err);
			});

		});

		it('should fail when payload is not the same', done => {
			header('my key id', 'my secret key', 'POST', '/endpoint', 'the payload', today)
			.then(data => {
				return header.verify(data, 'POST', '/endpoint', 'different payload', today, (keyid, cb) => { cb(null, 'my secret key'); });
			})
			.then(() => {
				done(new Error('Should not get here.'));
			})
			.catch(err => {
				expect(err.message).to.equal('Hash does not match.');
				done();
			})
			.catch(err => {
				done(err);
			});

		});

		it('should fail if time diff is more than 24h', done => {
			header.verify('ss1 keyid=my key id, hash=afc7e506a3e77a55d64ad2744d0f7a02d3bd9128ef1bf5eff04620c4b6fdd4e417b70893566edcef6ada6a4c5d76099c98bb06bfec5b93a1be793fdaba808ab9, nonce=6591a74c5b9e6c2b41d371b93bf08c12618ed866c000746dfca5764f6706666ea2ed1fbf4538313f2fb7da30a509a3423e976008734c73918751c1b403a24373',  'POST', '/endpoint', 'the payload', yesturday)
			.then(() => {
				done(new Error('Should not get here.'));
			})
			.catch(err => {
				expect(err.message).to.equal('Too big time difference.');
				done();
			})
			.catch(err => {
				done(err);
			});
		});

		it('should accept params in non-standard order', done => {
			header('my key id', 'my secret key', 'POST', '/endpoint', 'the payload', today)
			.then(data => {

				let part = data.split(',').map(str => str.trim())
				.reduce((pre, cur) => {
					let [key, val] = cur.replace(/^([^: ]+: ){0,1}ss1 /, '').split('=');
					pre[key] = val;
					return pre;
				}, {});

				return 'ss1 nonce=' + part['nonce'] + ', hash=' + part['hash'] + ', keyid=' + part['keyid'];
			})
			.then(data => {
				return header.verify(data, 'POST', '/endpoint', 'the payload', today, (keyid, cb) => { cb(null, 'my secret key'); });
			})
			.then(() => done())
			.catch(err => done(err));
		});

		it('should fail if format has too many params', done => {
			header.verify('ss1 keyid=my key id, realm=wtf, hash=afc7e506a3e77a55d64ad2744d0f7a02d3bd9128ef1bf5eff04620c4b6fdd4e417b70893566edcef6ada6a4c5d76099c98bb06bfec5b93a1be793fdaba808ab9, nonce=6591a74c5b9e6c2b41d371b93bf08c12618ed866c000746dfca5764f6706666ea2ed1fbf4538313f2fb7da30a509a3423e976008734c73918751c1b403a24373', 'POST', '/endpoint', 'the payload', today)
			.then(() => {
				done(new Error('Should not get here.'));
			})
			.catch(err => {
				expect(err.message).to.equal('Wrong header format.');
				done();
			})
			.catch(err => {
				done(err);
			});
		});

		it('should fail if not all params are in the string', done => {
			header.verify('ss1 keyid=my key id, hash=afc7e506a3e77a55d64ad2744d0f7a02d3bd9128ef1bf5eff04620c4b6fdd4e417b70893566edcef6ada6a4c5d76099c98bb06bfec5b93a1be793fdaba808ab9', 'POST', '/endpoint', 'the payload', today)
			.then(() => {
				done(new Error('Should not get here.'));
			})
			.catch(err => {
				expect(err.message).to.equal('Wrong header format.');
				done();
			})
			.catch(err => {
				done(err);
			});
		});

		it('should fail with same error if error is passed from keyfn', done => {
			header('my key id', 'my secret key', 'POST', '/endpoint', 'the payload', today)
			.then(data => {
				return header.verify(data, 'POST', '/endpoint', 'the payload', today, (keyid, cb) => { cb(new Error('My Test Error')); });
			})
			.then(() => {
				done(new Error('Should not get here.'));
			})
			.catch(err => {
				expect(err.message).to.equal('My Test Error');
				done();
			})
			.catch(err => {
				done(err);
			});

		});

		it('should fail with no-such-key-error if keyfn returns nothing', done => {
			header.verify('ss1 keyid=my key id, hash=afc7e506a3e77a55d64ad2744d0f7a02d3bd9128ef1bf5eff04620c4b6fdd4e417b70893566edcef6ada6a4c5d76099c98bb06bfec5b93a1be793fdaba808ab9, nonce=6591a74c5b9e6c2b41d371b93bf08c12618ed866c000746dfca5764f6706666ea2ed1fbf4538313f2fb7da30a509a3423e976008734c73918751c1b403a24373', 'POST', '/endpoint', 'payload', today, (keyid, cb) => { cb(); })
			.then(data => {
				done(new Error('Should not get here.'));
			})
			.catch(err => {
				expect(err.message).to.equal('No such key.');
				done();
			})
			.catch(err => {
				done(err);
			});
		});

	});

});
