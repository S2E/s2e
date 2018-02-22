#!/bin/sh
# The RST renderer in Sphinx and Github are not fully compatible with each other.
# This script makes a copy of the rst sources, patches them, and builds them with Sphinx.
# The original source should be kept as much as possible in Github's dialect so that people
# may use Github to browse the documentation.


# Copy files into a temp folder, then patch them to make sphinx happy
mkdir -p source1
cp -rp ../README.rst source1
cp -rp ../src source1
$(cd source1 && sed -i 's/number-lines/linenos/g' $(find . -name '*.rst'))

# rsync modified files
mkdir -p source
rsync -v -cr --delete source1/* source/

make html

echo "Replacing .rst with .html in links"
$(cd build/html && sed -i 's/\.rst\"/\.html\"/g' $(find . -name '*.html'))
