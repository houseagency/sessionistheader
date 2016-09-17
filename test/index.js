const expect = require('chai').expect;
const header = require('../index');

describe('Module', () => {

	describe('creating header', () => {

		it('should provide a callback interface', done => {
			header('my key id', 'my secret key', 'the payload', (err, data) => {
				done();
			});
		});

		it('should provide a promise interface', done => {
			header('my key id', 'my secret key', 'the payload')
			.then(data => {
				done();
			});
		});

		it('should return a string', done => {
			header('my key id', 'my secret key', 'the payload')
			.then(data => {
				expect(data).to.be.a('string');
			})
			.done(done);
		});

		it('should return a string starting with our scheme identifyer', done => {
			header('my key id', 'my secret key', 'the payload')
			.then(data => {
				expect(data.substr(0, 4)).to.equal('ss1 ');
			})
			.done(done);
		});

		it('should return a string with proper length', done => {
			header('my key id', 'my secret key', 'the payload')
			.then(data => {
				expect(data.length).to.equal(309);
			})
			.done(done);
		});

	});

	describe('verifying header', () => {

		it('should provide a callback interface', done => {
			header.verify('the header str', 'the payload', (keyid, cb) => { cb(null, 'the secret key'); }, (err, data) => {
				done();
			});
		});

		it('should provide a promise interface', done => {
			header.verify('the header str', 'the payload', (keyid, cb) => { cb(null, 'the secret key'); })
			.then(data => {
				done();
			})
			.catch(err => {
				done();
			});
		});

		it('should be able to verify headers created by the module', done => {
			header('my key id', 'my secret key', 'the payload')
			.then(data => {
				return header.verify(data, 'the payload', (keyid, cb) => { cb(null, 'my secret key'); });
			})
			.then(() => {
				done();
			})
			.catch(err => {
				done(err);
			});

		});

		it('should fail when secret key is not the same', done => {
			header('my key id', 'my secret key', 'the payload')
			.then(data => {
				return header.verify(data, 'the payload', (keyid, cb) => { cb(null, 'another secret key'); });
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
			header('my key id', 'my secret key', 'the payload')
			.then(data => {
				return header.verify(data, 'different payload', (keyid, cb) => { cb(null, 'my secret key'); });
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
			header.verify('ss1 keyid=my key id, hash=afc7e506a3e77a55d64ad2744d0f7a02d3bd9128ef1bf5eff04620c4b6fdd4e417b70893566edcef6ada6a4c5d76099c98bb06bfec5b93a1be793fdaba808ab9, salt=6591a74c5b9e6c2b41d371b93bf08c12618ed866c000746dfca5764f6706666ea2ed1fbf4538313f2fb7da30a509a3423e976008734c73918751c1b403a24373, time=1000000000000')
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

		it('should fail if format has too many params', done => {
			header.verify('ss1 keyid=my key id, realm=wtf, hash=afc7e506a3e77a55d64ad2744d0f7a02d3bd9128ef1bf5eff04620c4b6fdd4e417b70893566edcef6ada6a4c5d76099c98bb06bfec5b93a1be793fdaba808ab9, salt=6591a74c5b9e6c2b41d371b93bf08c12618ed866c000746dfca5764f6706666ea2ed1fbf4538313f2fb7da30a509a3423e976008734c73918751c1b403a24373, time=' + (new Date()).getTime())
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
			header.verify('ss1 keyid=my key id, hash=afc7e506a3e77a55d64ad2744d0f7a02d3bd9128ef1bf5eff04620c4b6fdd4e417b70893566edcef6ada6a4c5d76099c98bb06bfec5b93a1be793fdaba808ab9, time=' + (new Date()).getTime())
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

	});

});