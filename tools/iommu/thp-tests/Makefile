# Create a static thp-tests.a library
# The final program must also implement device-specific functions declared in
# thp-dma.h. Link it with -pthread

CC		= $(CROSS_COMPILE)gcc
include ../../scripts/Makefile.include

ifeq ($(srctree),)
SRC		:= $(CURDIR)/
srctree 	:= $(SRC)../../../
else
SRC		:= $(srctree)/tools/iommu/thp-tests/
endif

CFLAGS 		+= -Wall -O2
CFLAGS		+= -I$(srctree)/tools/include
CFLAGS		+= -I$(objtree)/usr/include

DEBUG		= -DDEBUG
CFLAGS		+= $(DEBUG)
CFLAGS		+= -pthread

OBJS		= $(addprefix $(OUTPUT),thp-tests.o thp-utils.o)

THP_TESTS	= $(OUTPUT)thp-tests.a

all: $(THP_TESTS)

$(OUTPUT)%.o: %.c thp-utils.h Makefile
	$(CC) $(CFLAGS) -c -o $@ $<

$(THP_TESTS): $(OBJS)
	ar rcs $@ $^

clean:
	$(RM) $(OBJS) $(THP_TESTS)
