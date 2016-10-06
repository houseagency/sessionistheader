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
* All requests to the server must include a `Date:` HTTP header with the
current time in `RFC2616` format. The server should not accept times
older/newer than 24h from the current time.

Header format
--------------

The Sessionist Authorization HTTP Header is used for both authorization and
verifying the body payload (checksum) of API requests.

Format is:

	Authorization: ss1 keyid=<keyid>, hash=<hash>, nonce=<nonce>

### keyid

See more info about the "key id" in the "Principles" section above.

### hash

The hash is a SHA-512 HMAC (`RFC2104`) in lower case hex format,
created like this:

	HMAC(secret_key, nonce || method || path || payload || date)

Where:

* `||` means concatination.
* `secret_key` is the assigned to the client (and identified by the `keyid`).
* `nonce` is the nonce in binary format (not in hex).
* `method` is the HTTP method for the request, in uppercase letters.
* `path` is the path of the request (including query string, if there is one).
* `payload` is the HTTP body payload.
* `date` is the content of the `Date:` HTTP header, i.e. the current time of
  the client in `RFC2616` format.

### nonce 

A random 512 bit value in lower case hex format. Should be generated on every
request using some good random generator.


