# -*- coding: utf-8 -*-

CLIENT_ID = "4d2302d52b5ee74918000009"
REDIRECT_URI = "http://localhost:8080/trac_env_test/auth_server_process"
AUTHORIZE_URL = "http://example.com:7070/oauth2/authorize"
CLIENT_SECRET = "some secret string"
TOKEN_URL = "http://example.com:7070/oauth2/token"
AUTHS_URL = "http://example.com:7070/auth"


try:
  import json
except ImportError:
  import simplejson
import urllib

from genshi.builder import tag
from trac.web import HTTPBadRequest, HTTPUnauthorized
from trac.web.auth import LoginModule


class AuthServerPlugin(LoginModule):
  """Enables an user to log-in using auth_server.
  """

  # INavigationContributor methods
  def get_active_navigation_item(self, req):
    return 'auth_server_login'

  def get_navigation_items(self, req):
    if not req.authname or req.authname == 'anonymous':
      yield ('metanav', 'login', 
             tag.a(('AuthServer Login'), href=req.href.auth_server_login()))

  # IRequestHandler methods
  def match_request(self, req):
    return req.path_info in ['/auth_server_login', '/auth_server_process'] or \
           LoginModule.match_request(self, req)

  def process_request(self, req):
    if req.path_info == "/auth_server_login":
      self._redirects_for_login(req)
    if req.path_info == "/auth_server_process":
      self._do_process(req)
    else:
      LoginModule.process_request(self, req)

  def _redirects_for_login(self, req):
    """Redirects the user to auth_server for login.
    """
    state = self._referer(req) or req.abs_href() # Use state to contain next url.
    args = dict(client_id=CLIENT_ID, response_type="code", 
                redirect_uri=REDIRECT_URI, state=state)
    url = "%s?%s" % (AUTHORIZE_URL, urllib.urlencode(args))
    req.redirect(url)

  def _do_process(self, req):
    """Process grant returned by user.
    """
    code = req.args.get('code')
    next = req.args.get('state') or req.base_path or "/"
    if not code: 
      raise HTTPBadRequest('"code" parameter is missing.')

    args = dict(client_id=CLIENT_ID, 
                redirect_uri=REDIRECT_URI,
                client_secret=CLIENT_SECRET,
                grant_type= "authorization_code",
                code=code)
    qs = urllib.urlencode(args)
    try:
      res = urllib.urlopen(TOKEN_URL, qs).read()
      data = json.loads(res)
    except (IOError, ValueError):
      raise HTTPBadRequest('Bad request. %s' % res)

    access_token = data.get('access_token')
    if not access_token: 
      error_msg = data.get('error', {}).get('message', '')
      raise HTTPUnauthorized("You are not authorized. %s" % error_msg)

    access_token = data.get('access_token')
    if not access_token:
      raise HTTPUnauthorized("You are not authorized.")

    # Get info and roles of the user:
    url = '%s?oauth_token=%s' % (AUTHS_URL, access_token)
    try:
      res = urllib.urlopen(url).read()
      info = json.loads(res)
    except (IOError, ValueError):
      raise HTTPBadRequest('Bad answer from auth_server: %s' % res)

    print "info:", info
    # TODO: 403 if not good authorizations

    # We cannot directly write into req.remote_user, so write in environ
    # and let LoginModule set cookie stuff as needed...
    req.environ['REMOTE_USER'] = info.get('email')
    LoginModule._do_login(self, req)
    req.redirect(next)

