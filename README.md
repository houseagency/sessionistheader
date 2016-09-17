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

