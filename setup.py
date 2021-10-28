
import os
import sys
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst')) as f:
    README = f.read()

with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = ['pyramid>=2,<3']

setup(name='pyramid_multiauth',
      version='1.0.1.dev0',
      description='pyramid_multiauth',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
          "Programming Language :: Python",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.7",
          "Programming Language :: Python :: 3.8",
          "Programming Language :: Python :: 3.9",
          "Framework :: Pylons",
          "Topic :: Internet :: WWW/HTTP",
          "Development Status :: 5 - Production/Stable",
          "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
      ],
      author='Mozilla Services',
      author_email='services-dev@mozilla.org',
      url='https://github.com/mozilla-services/pyramid_multiauth',
      keywords='web pyramid pylons authentication',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="pyramid_multiauth")
