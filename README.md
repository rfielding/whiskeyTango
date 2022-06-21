Whiskey Tango
=============

This is a simplified web token format that has the property that you can't get aaccess to the claims unless you followed the correct signature check protocol.  Most of the problems with JWT have to do with the fact that its design allows a large number of hazardous practices.

- It has a complex RFC that goes beyond the simple and easy to understand uses of jwt.io, making it difficult to implement correctly.

- When correctly implemented, it is full of hazards that should be disabled completely.  So this implies that implementing the full standard is a security hazard.

- One hazard is that the algorithm is specified by the token.  A trivial to forge token such as an `alg:None` token is considered valid.  Things like this make JWTs hazardous to handle.

- The other hazard is that it is possible to retrieve claims without bothering to check the signature.  The format encourages this.  Because JWTs are checked from many languages, it's highly probable that some clients will just extract the claims and hope that somebody else did the signature check; if they even care.

- Another hazard is that the JWT itself tells a client where to download the trust for the file.  The token should not be telling you where to do this, because real libraries deal with this by automatically downloading the trust of unknown files.  This completely defeats the point of doing a signature check in the first place.  A better idea is that if you have a trust store, such as a JWK, you may want to have the trust file add information to help rotate to new signing keys.  This means that the trust file, that you actually trust; tells you how to do this, instead of a JWT that you don't trust.  This basically means that the `alg` field should go away from JWT, and the details of how signing happens should be in the trust file that includes a JWK.

Encrypted JWTs involve a complex specification in JOSE, that just compounds the complexity problem associated with JWT hazards.  There are many situations where the CA has the signing key, and only clients allowed to decrypt the claims need to check the validity of those claims.  So, the public keys to verify a JWT can actually be secrets in that situation.

The good part of JWT is the idea of a simple json object that is digitally signed.  The existing JWT specification goes roughly like this:

$$
jwt = join(".", [B64UEncode(header), B64UEncode(body), B64UEncode(signature)]
$$
