from setuptools import setup

PACKAGE = 'TracAuthServer'
VERSION = '0.0.1'

setup(
  name=PACKAGE,
  version=VERSION,
  description='AuthServer plugin for Trac',
  keywords='authserver trac oauth2 authentication authorization',
  license='Trac license (modified BSD)',
  author='Pierre Ruyssen (AF83)',
  author_email='pierre@ruyssen.eu',
  url='https://github.com/AF83/trac_auth_server',
  packages=['trac_auth_server'],
  entry_points={'trac.plugins': '%s = trac_auth_server' % PACKAGE},
  include_package_data = True,
  package_data={},
  install_requires = [
    'AuthServerClient==0.0.1'
  ],
  classifiers=[
    "Development Status :: 3 - Alpha",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: BSD License",
    "Programming Language :: Python",
    "Topic :: Internet :: WWW/HTTP",
    "Topic :: Software Development :: Bug Tracking",
  ],
)

