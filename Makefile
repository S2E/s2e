RST_FILES?=$(filter-out README.rst,$(wildcard *.rst src/*.rst src/*/*.rst))
HTML_FILES?=$(RST_FILES:.rst=.html)

all: $(HTML_FILES)

clean:
	rm -f $(HTML_FILES)

%.html: %.rst
	./src/rst2html-pygments                                                             \
	    --stylesheet=$$(echo $< | sed -e 's:[^/]\+/:../:g' | xargs dirname)/src/s2e.css \
	    --link-stylesheet --source-link --no-toc-backlinks                              \
	    --input-encoding utf-8:strict $< $@
	sed -i 's/\.rst/\.html/' $@
	sed -i 's/$(basename $(notdir $@))\.html/$(basename $(notdir $@)).rst/' $@
