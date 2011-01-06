# -*- coding: utf-8 -*-

from genshi.builder import tag
from trac.web import HTTPBadRequest, HTTPUnauthorized, HTTPInternalError
from trac.web.auth import LoginModule

from auth_server_client import oauth2


oauth2.init("4d2302d52b5ee74918000009", 
            "http://localhost:8080/trac_env_test/auth_server_process",
            "some secret string",
            "http://example.com:7070/oauth2/authorize",
            "http://example.com:7070/oauth2/token",            
            "http://example.com:7070/auth")


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
    url = oauth2.get_login_url(state)
    req.redirect(url)

  def _do_process(self, req):
    """Process grant returned by user.
    """
    code = req.args.get('code')
    next = req.args.get('state') or req.base_path or "/"
    if not code: 
      raise HTTPBadRequest('"code" parameter is missing.')

    try:
      access_token = oauth2.process_code(code)
    except ValueError, err:
      raise HTTPBadRequest('Bad request. %s' % err)
    except AssertionError, err:
      raise HTTPUnauthorized("You are not authorized. %s" % err)

    try:
      info = oauth2.get_authorizations(access_token)
    except ValueError, err:
      raise HTTPInternalError('Bad answer from auth_server: %s' % err)

    print "info:", info
    # TODO: 403 if not good authorizations

    # We cannot directly write into req.remote_user, so write in environ
    # and let LoginModule set cookie stuff as needed...
    req.environ['REMOTE_USER'] = info.get('email')
    LoginModule._do_login(self, req)
    req.redirect(next)

