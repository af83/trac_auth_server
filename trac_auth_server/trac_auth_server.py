# -*- coding: utf-8 -*-

from genshi.builder import tag
from trac.core import Component, implements
from trac.web import HTTPBadRequest, HTTPUnauthorized, HTTPInternalError
from trac.web.api import IRequestFilter
from trac.web.auth import LoginModule

from auth_server_client import oauth2


class NoAnonymousAuthServerPlugin(Component):
  """Redirects user to auth_server when not logged-in.
  """
  implements(IRequestFilter)

  # IRequestFilter methods
  def pre_process_request(self, req, handler):
    if req.path_info.startswith('/auth_server_') or req.authname != 'anonymous':
      return handler
    state = req.abs_href() + req.path_info
    url = oauth2.get_login_url(state)
    req.redirect(url)

  def post_process_request(self, req, template, data, content_type):
    return template, data, content_type


class AuthServerPlugin(LoginModule):
  """Enables an user to log-in using auth_server.
  """

  def __init__(self):
    # Init oauth2 client according to config:
    options = ['client_id', 'process_url', 'client_secret', 'authorize_url',
               'token_url', 'auth_url']
    args = [self.config.get('trac_auth_server', key) for key in options]
    oauth2.init(*args)

  # INavigationContributor methods
  # To Add a link to log-in using auth_server
  def get_active_navigation_item(self, req):
    return 'auth_server_login'

  def get_navigation_items(self, req):
    if not req.authname or req.authname == 'anonymous':
      yield ('metanav', 'login', 
             tag.a(('AuthServer Login'), href=req.href.auth_server_login()))


  # IRequestHandler methods
  # To handle login / logout / process
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
    state = self._referer(req) # Use state to contain next url.
    if not state or "/auth_server_" in state: 
      # we don't want to be redirected on a auth_server_* url.
      state = req.abs_href()
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
      raise HTTPInternalError(str(err))

    print "info:", info
    # TODO: 403 if not good authorizations

    # We cannot directly write into req.remote_user, so write in environ
    # and let LoginModule set cookie stuff as needed...
    req.environ['REMOTE_USER'] = info.get('email')
    LoginModule._do_login(self, req)
    req.redirect(next)

