#!/bin/bash

if [[ -z $WORKSPACE ]]
then
    export WORKSPACE=$(pwd)
fi

cd $WORKSPACE

JUNK=/var/tmp/junk.txt

for dir in \
    src \
    vendor/path/to/project
do
    if [ -d "$dir" ]; then
        find $dir -name '*.php' >> $JUNK
    fi
done

cat $JUNK | \
    grep -v "junk_file.php" | \
    grep -v "junk/directory.php" | \
    awk '!x[$0]++'

rm $JUNK
