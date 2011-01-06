# Trac AuthServer Plugin

## Description

Plugin for trac to use [AuthServer](https://github.com/af83/auth_server) for authentication and authorization.


## Installation

    python setup.py install


## Configuration

You must enable the Plugin in the components section (trac.web.auth.* must not be disabled):

    [components]
    # trac.web.auth.* = disabled
    trac_auth_server.* = enabled


Then you must specify the following values in the trac_auth_server section:

  - client_id: ID of the auth_server client.
  - process_url: OAuth2 process url. Must end with '/auth_server_process'.
  - client_secret: shared secret btween client and oauth2 server.
  - authorize_url: OAuth2 authorize URL.
  - token_url: OAuth2 token URL.
  - auth_url: Auth resource server endpoint to get authorizations.


Example:

    [trac_auth_server]
    client_id = 4d2302d52b5ee74918000009
    process_url = http://trac.net/trac_env_test/auth_server_process
    client_secret = some secret string
    authorize_url = http://auth_server.com:7070/oauth2/authorize
    token_url = http://auth_server.com:7070/oauth2/token
    auth_url = http://auth_server.com:7070/auth


## License
This software is licensed using the same licence as Trac:  http://trac.edgewall.org/wiki/TracLicense.

