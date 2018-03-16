Sessionist Authorization HTTP Header
=====================================

[![Build Status](https://semaphoreci.com/api/v1/houseagency/sessionistheader/branches/master/shields_badge.svg)](https://semaphoreci.com/houseagency/sessionistheader)

This JavaScript module creates and verifies the Sessionist Authorization HTTP
Header.

How to create a valid header
-----------------------------

	const sessionistHeader = require('sessionistheader');

	let myKeyId = '4bc0093d';
	let mySecretKey = '3485eac0182ef8123c116fc8392b34e817268e292';
	let theHttpMethod = 'PUT';
	let theHttpPath = '/api/v1/myservice?cool=very';
	let theBodyPayload = '{ "whatever": "is in the body of the http request" }';
	let theHttpDate = 'Thu, 06 Oct 2016 22:27:21 GMT';

	// myKeyId is an identifier for your secret key.
	// mySecretKey is the secret key.
	// theHttpMethod is an uppercase string with the method, like "GET" or "POST"
	// theHttpPath is the path (including querystring) for the request.
	// theBodyPayload is the raw body content of the request.
	// theHttpDate is the current time in RFC2616 format.

	sessionistHeader(myKeyId, mySecretKey, theHttpMethod, theHttpPath, theBodyPayload, theHttpDate, (err, auth) => {
		// The proper header string is now in the auth variable
		req.setHeader('Authorization', auth);
		req.setHeader('Date', theHttpDate); // Must also be set!
	});


How to use the Promise interface
---------------------------------

	sessionistHeader(myKeyId, mySecretKey, theHttpMethod, theHttpPath, theBodyPayload, theHttpDate)
	.then(auth => req.setHeader('Authorization', auth);

How to verify an Authorization header
--------------------------------------

	const keyfn = (keyid, callback) => {
		// This function should find the corresponding secret key to
		// the given keyid, and then call the callback function, which
		// take two parameters: err and secretkey:
		callback(null, 'the topsecret key');
	};

	verify(headerStr, theHttpMethod, theHttpPath, theBodyPayload, theHttpDate, keyfn)
	.then(() => {
		// Yes, verified successfully!
	})
	.catch(err => {
		// Nope. Not verified.
	});


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


TODO / On the road map before version 1.0
-----------------------------------------

* Ensuring compatibility with nodejs Buffers for the body payload.

