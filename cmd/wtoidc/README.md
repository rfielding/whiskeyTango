wtoidc
=======

This is a minimal oidc provider based on whiskeyTango.
The point is to do simplistic `openid-connect` protocol
for `grant_type` of `password` and `refresh_token`. The point
is to have something that is vastly simpler to setup, without
a bewildering array of options to sift through and support.

- `/openid-connect/tokens`
  - `grant_type=password` yields a `wt` token for which checking claims is cryptographically mandatory
    - inputs:
      - `username` the logged in user name
      - `password` the password at time of login
      - `client_id` the client role to run as
      - `client_secret` the optional password to run as a client, perhaps under no `username` and `password`
    - outputs:
      - `access_token` a `wt` token that is cryptographically mandatory to check, to prevent honoring unchecked claims
        - `exp` a unix timestamp in seconds for the expiration date is mandatory
      - `refres_token` an opaque token that this server can use to give a new `access_token` with an extended expiration date
  - `grant_type=refresh_token` gives back another opaque refresh token in which the original password was lost
- just store the users in a simple json file. make setup utterly trivial, especially in containerized setups.
- include a simple queue over http to send and receive messages. this lets this server run as a simple foundation for making applications. 

 
