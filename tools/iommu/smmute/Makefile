CC		= $(CROSS_COMPILE)gcc
include ../../scripts/Makefile.include

ifeq ($(srctree),)
SRC		:= $(CURDIR)/
srctree 	:= $(SRC)../../../
else
SRC		:= $(srctree)/tools/iommu/smmute/
endif

CFLAGS 		+= -Wall -O2
# Order matters: we need list.h first
CFLAGS		+= -I$(srctree)/tools/include
CFLAGS		+= -I$(srctree)/include/uapi

CFLAGS		+= -pthread
LIB_LDFLAGS	+= -pthread -lrt

SMMUTE		:= $(OUTPUT)smmute
DRIVERS		:= driver-kernel.o

ALL		+= $(SMMUTE)

OBJS		+= main.o lib.o
OBJS		+= $(DRIVERS)
OBJS		:= $(addprefix $(OUTPUT),$(OBJS))
comma		= ,
DEPS		:= $(foreach obj,$(OBJS),\
		  $(subst $(comma),_,$(dir $(obj)).$(notdir $(obj)).d))

depfile		= $(subst $(comma),_,$(dir $@).$(notdir $@).d)
DEPS_FLAGS	= -Wp,-MD,$(depfile) -Wp,-MT,$@

all: $(ALL)

$(OUTPUT)%.o: $(SRC)%.c
	$(CC) $(CFLAGS) $(DEPS_FLAGS) -c -o $@ $<

$(SMMUTE): $(addprefix $(OUTPUT),main.o lib.o $(DRIVERS))
	$(CC) -o $@ $^ $(LIB_LDFLAGS)

clean:
	rm -vf $(OUTPUT)*.o $(DEPS)

distclean: clean
	rm -vf $(ALL)

.PHONY: all clean distclean

-include $(DEPS)
