Sessionist Authorization HTTP Header
=====================================

This JavaScript module creates and verifies the Sessionist Authorization HTTP
Header.

How to create a valid header
-----------------------------

	const sessionistHeader = require('sessionistheader');

	let myKeyId = '4bc0093d';
	let mySecretKey = '3485eac0182ef8123c116fc8392b34e817268e292';
	let theBodyPayload = '{ "whatever": "is in the body of the http request" }';

	sessionistHeader(myKeyId, mySecretKey, theBodyPayload, (err, auth) => {
		// The proper header string is now in the auth variable
		req.setHeader('Authorization', auth);
	});

How to use the Promise interface
---------------------------------

	sessionistHeader(myKeyId, mySecretKey, theBodyPayload)
	.then(auth => req.setHeader('Authorization', auth);

Some principles regarding the Sessionist Authorization HTTP Header
-------------------------------------------------------------------

* This is a custom `RFC2617` Authorization header.
* The scheme identifier is `ss1`, where "ss" is short for "Sessionist"
and "1" tells this is version 1 of the Sessionist format.
* Clients should be assigned a "secret key" and a "key id" identifying the
secret key. The secret key should be kept secret and only be used for making
hashes/checksums. The key id, however, can be sent in clear text in the
header.

Header format
--------------

The Sessionist Authorization HTTP Header is used for both authorization and
verifying the body payload (checksum) of API requests.

Format is:

	Authorization: ss1 keyid=<keyid>, hash=<hash>, nonce=<nonce>, time=<time>

### keyid

See more info about the "key id" in the "Principles" section above.

### hash

The hash is a 512 bit hash/checksum value in lower case hex format.

It is caluclated this way:

	HASH(secret_key || HASH(nonce || HASH(secret_key || payload || time)))

Where:

* `||` means concatination.
* `payload` is the HTTP body payload.
* The `HASH()` function is SHA3-512.

### nonce 

A random 512 bit value in lower case hex format. Should be generated on every
request using some good random generator.

### time

The number of milliseconds since 1 Jan 1970 UTC (unix epoch time in
milliseconds), as a string.

The server should not accept times older/newer than 24h from the current time.

