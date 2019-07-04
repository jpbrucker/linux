include ../scripts/Makefile.include

all: thp-tests

thp-tests: thp-tests FORCE
	$(call descend,$@)

thp-tests_clean: FORCE
	$(call descend,$(@:_clean=),clean)

clean: thp-tests_clean FORCE

FORCE:

.PHONY: FORCE
