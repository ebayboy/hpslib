
PWD=$(shell pwd)
INCS= -I$(PWD)/hyperscan/include/

# change to you project name
MYLIB = libhps.a

# change to you project file dir
VPATH = common:test:waf_config:filter:log:waf:match:waf_match:deps
	# the obj dir
	OBJDIR = obj

###########################################################################
# source files
SRCSC = $(foreach dir,$(subst :, ,$(VPATH)),$(wildcard $(dir)/*.c))
	# obj files
	OBJSC_1 = $(addsuffix .o,$(basename $(SRCSC)))
	OBJSC = $(foreach n,$(notdir $(OBJSC_1)),$(OBJDIR)/$(n))

	# head files
	HEADERS = $(foreach dir,$(subst :, ,$(VPATH)),$(wildcard $(dir)/*.h))

CC = gcc
INCS += $(patsubst %,-I%,$(subst :, ,$(VPATH)))
	CFLAGS += $(INCS)

DEBUG = -g -ggdb -DDEBUG

all: $(MYLIB)

$(MYLIB): $(OBJSC) $(SRCSC) $(HEADERS)
	ar rcs $(MYLIB) $(OBJSC)
	ranlib $(MYLIB)
	cp $(HEADERS) ./include/
	cp $(MYLIB) ./lib/
	cp hyperscan/include/* ./include/
	cp hyperscan/lib/* ./lib/

# *.c file commpare
$(OBJSC): $(SRCSC) $(HEADERS)
	@test -d $(OBJDIR) | mkdir -p $(OBJDIR)
	$(CC) -c $(SRCSC) $(INCS)  $(DEBUG)
	mv *.o $(OBJDIR)/

clean:
	rm -rf $(OBJDIR)
	rm -f *.o *.a
	rm -rf ./include/*
	rm -rf ./lib/*
