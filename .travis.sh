#!/bin/bash

set -xe

wget https://github.com/nikic/php-ast/archive/master.zip
unzip master.zip
cd php-ast-master/
phpize
./configure
make
sudo make install && echo "extension=<extension>.so" >> ~/.phpenv/versions/$(phpenv version-name)/etc/php.ini
