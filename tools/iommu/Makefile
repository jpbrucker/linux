include ../scripts/Makefile.include

all: smmute thp-tests

smmute thp-tests: thp-tests FORCE
	$(call descend,$@)

smmute_clean thp-tests_clean: FORCE
	$(call descend,$(@:_clean=),clean)

clean: smmute_clean thp-tests_clean FORCE

FORCE:

.PHONY: FORCE
