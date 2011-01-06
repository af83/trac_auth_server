from setuptools import setup

PACKAGE = 'TracAuthServer'
VERSION = '0.0.1'

setup(
  name=PACKAGE,
  version=VERSION,
  description='AuthServer plugin for Trac',
  license='Trac license',
  author='Pierre Ruyssen (AF83)',
  author_email='pierre@ruyssen.fr',
  url='',
  packages=['trac_auth_server'],
  entry_points={'trac.plugins': '%s = trac_auth_server' % PACKAGE},
  include_package_data = True,
  package_data={},
  install_requires = [
    'AuthServerClient==0.0.1'
  ],
)

