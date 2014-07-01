# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup

install_requires = [
    'netaddr==0.7.11',
    'minion-backend'
]

setup(name="minion-masscan-plugin",
      version="0.1",
      description="MASSCAN Plugin for Minion",
      url="https://github.com/0xd012/minion-masscan-plugin/",
      author="Laurent Butti",
      author_email="laurent.butti@gmail.com",
      packages=['minion', 'minion.plugins'],
      namespace_packages=['minion', 'minion.plugins'],
      include_package_data=True,
      install_requires = install_requires)
