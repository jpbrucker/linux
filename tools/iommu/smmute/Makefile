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
CFLAGS		+= -I$(objtree)/usr/include

CFLAGS		+= -pthread
LIB_LDFLAGS	+= -pthread -lrt

SMMUTE		:= $(OUTPUT)smmute
MULTI		:= $(OUTPUT)smmute-multi
TEST_VFIO	:= $(OUTPUT)test-vfio
TEST_FAULT	:= $(OUTPUT)smmute-fault
TEST_REPLAY	:= $(OUTPUT)test-vfio-replay
SERVER		:= $(OUTPUT)smmuted
TEST_BIND	:= $(OUTPUT)smmute-bind
DRIVERS		:= driver-kernel.o driver-vfio.o driver-ipc.o

ALL		+= $(SMMUTE)
ALL		+= $(MULTI)
ALL		+= $(SERVER)
ALL		+= $(TEST_VFIO)
ALL		+= $(TEST_FAULT)
ALL		+= $(TEST_REPLAY)
ALL		+= $(TEST_BIND)

OBJS		+= main.o lib.o
OBJS		+= ipc-server.o
OBJS		+= multi.o
OBJS		+= test-vfio.o
OBJS		+= smmute-fault.o
OBJS		+= vfio-replay.o
OBJS		+= smmute-bind.o
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

$(SERVER): $(addprefix $(OUTPUT),ipc-server.o lib.o $(DRIVERS))
	$(CC) -o $@ $^ $(LIB_LDFLAGS)

$(MULTI): $(addprefix $(OUTPUT),multi.o lib.o $(DRIVERS))
	$(CC) -o $@ $^ $(LIB_LDFLAGS)

$(TEST_VFIO): $(addprefix $(OUTPUT),test-vfio.o lib.o $(DRIVERS))
	$(CC) -o $@ $^ $(LIB_LDFLAGS)

$(TEST_FAULT): $(addprefix $(OUTPUT),smmute-fault.o lib.o $(DRIVERS))
	$(CC) -o $@ $^ $(LIB_LDFLAGS)

$(TEST_REPLAY): $(addprefix $(OUTPUT),vfio-replay.o lib.o $(DRIVERS))
	$(CC) -o $@ $^ $(LIB_LDFLAGS)

$(TEST_BIND): $(addprefix $(OUTPUT),smmute-bind.o lib.o $(DRIVERS))
	$(CC) -o $@ $^ $(LIB_LDFLAGS)

clean:
	rm -vf $(OUTPUT)*.o $(DEPS)

distclean: clean
	rm -vf $(ALL)

.PHONY: all clean distclean

-include $(DEPS)
