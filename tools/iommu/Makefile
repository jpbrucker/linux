include ../scripts/Makefile.include

all: smmute

smmute: FORCE
	$(call descend,$@)

smmute_clean: FORCE
	$(call descend,$(@:_clean=),clean)

clean: smmute_clean FORCE

FORCE:

.PHONY: FORCE
