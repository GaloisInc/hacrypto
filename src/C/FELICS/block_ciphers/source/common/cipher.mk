#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
#
# This file is part of FELICS.
#
# FELICS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# FELICS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

#
# Call this makefile from a cipher source directory or build directory to build 
#	... the given cipher:
#	make -f ./../../../common/cipher.mk [ARCHITECTURE=[AVR|MSP|ARM|PC]]
#		[DEBUG=[0|1|3|7]] [MEASURE_CYCLE_COUNT=[0|1]] [SCENARIO=[0|1|2]] 
#		[COMPILER_OPTIONS='...'] [all|clean|cleanall|help]
#
# 	Examples: 
#		make -f ./../../../common/cipher.mk
#		make -f ./../../../common/cipher.mk ARCHITECTURE=PC DEBUG=1
#			SCENARIO=0
#		make -f ./../../../common/cipher.mk clean
#


PCMAKEFILE = ./../../../architecture/pc.mk
AVRMAKEFILE = ./../../../architecture/avr.mk
MSPMAKEFILE = ./../../../architecture/msp.mk
ARMMAKEFILE = ./../../../architecture/arm.mk


SOURCEDIR = ./../source
BUILDDIR = ./../build

COMMONSOURCEDIR = ./../../../common
SCENARIO1SOURCEDIR = $(COMMONSOURCEDIR)/scenario1
SCENARIO2SOURCEDIR = $(COMMONSOURCEDIR)/scenario2


INCLUDES = -I$(SOURCEDIR) -I$(COMMONSOURCEDIR)

VPATH = $(SOURCEDIR):$(COMMONSOURCEDIR)


SOURCES = $(wildcard $(SOURCEDIR)/*.c)
OBJS = $(subst $(SOURCEDIR)/, , $(SOURCES:.c=.o))

SCENARIO1SOURCES = $(wildcard $(SCENARIO1SOURCEDIR)/*.c)
SCENARIO1ALLOBJS = $(subst $(SCENARIO1SOURCEDIR)/, , $(SCENARIO1SOURCES:.c=.o))
SCENARIO1OBJS = $(filter-out scenario1.o, $(SCENARIO1ALLOBJS))

SCENARIO2SOURCES = $(wildcard $(SCENARIO2SOURCEDIR)/*.c)
SCENARIO2ALLOBJS = $(subst $(SCENARIO2SOURCEDIR)/, , $(SCENARIO2SOURCES:.c=.o))
SCENARIO2OBJS = $(filter-out scenario2.o, $(SCENARIO2ALLOBJS))

LSTS = $(OBJS:.o=.lst)
CIPHERLSTS = main.lst common.lst
SCENARIO1LSTS=$(SCENARIO1OBJS:.o=.lst)
SCENARIO2LSTS=$(SCENARIO2OBJS:.o=.lst)


ifeq ($(SCENARIO), 1)
TARGET=target1
LSTS += $(SCENARIO1LSTS)
else
ifeq ($(SCENARIO), 2)
TARGET=target2
LSTS += $(SCENARIO2LSTS)
else
TARGET=target
LSTS += $(CIPHERLSTS)
endif
endif


CURRENTPATHDIRS = $(subst /, , $(CURDIR))
LASTCURRENTPATHDIR = $(word $(words $(CURRENTPATHDIRS)), $(CURRENTPATHDIRS))
CIPHERNAME = $(lastword $(subst $(LASTCURRENTPATHDIR), , $(CURRENTPATHDIRS)))  


DELIMITER = ----------


.PHONY : all clean cleanall help


all : post-build

.PHONY : post-build
post-build : main-build
	@echo $(DELIMITER) End building $(CIPHERNAME) $(DELIMITER)

.PHONY : main-build
main-build : \
		pre-build \
		$(TARGET)

.PHONY : pre-build
pre-build : \
		pre-build-include \
		pre-build-debug \
		pre-build-scenario \
		pre-build-measure_cycle_count \
		pre-build-compiler_options
	@echo $(DELIMITER) Start building $(CIPHERNAME) $(DELIMITER)

.PHONY : pre-build-include
pre-build-include :
ifeq ($(ARCHITECTURE), AVR)
	@echo Building for $(ARCHITECTURE) ...
include $(AVRMAKEFILE)
$(eval CFLAGS += -D $(ARCHITECTURE))
else
ifeq ($(ARCHITECTURE), MSP)
	@echo Building for $(ARCHITECTURE) ...
include $(MSPMAKEFILE)
$(eval CFLAGS += -D $(ARCHITECTURE))
else
ifeq ($(ARCHITECTURE), ARM)
	@echo Building for $(ARCHITECTURE) ...
include $(ARMMAKEFILE)
$(eval CFLAGS += -D $(ARCHITECTURE))
else
	@echo Building for PC ...
include $(PCMAKEFILE)
$(eval CFLAGS += -D PC)
endif
endif
endif

.PHONY : pre-build-debug
pre-build-debug :
ifdef DEBUG
	@echo Building with DEBUG flag set to $(DEBUG) ...
$(eval CFLAGS += -D DEBUG=$(DEBUG))
else
	@echo Building with DEBUG flag NOT set ...
endif

.PHONY : pre-build-scenario
pre-build-scenario :
ifdef SCENARIO
	@echo Building with SCENARIO flag set to $(SCENARIO) ...
$(eval CFLAGS += -D SCENARIO=$(SCENARIO))
else
	@echo Building with SCENARIO flag NOT set ...
endif

.PHONY : pre-build-measure_cycle_count
pre-build-measure_cycle_count :
ifdef MEASURE_CYCLE_COUNT
	@echo Building with MEASURE_CYCLE_COUNT flag set to $(MEASURE_CYCLE_COUNT) \
		...
$(eval CFLAGS += -D MEASURE_CYCLE_COUNT=$(MEASURE_CYCLE_COUNT))
else
	@echo Building with MEASURE_CYCLE_COUNT flag NOT set ...
endif

.PHONY : pre-build-compiler_options
pre-build-compiler_options :
ifdef COMPILER_OPTIONS
	@echo Building with COMPILER_OPTIONS flag set to $(COMPILER_OPTIONS) ...
$(eval CFLAGS += $(COMPILER_OPTIONS))
else
	@echo Building with COMPILER_OPTIONS flag NOT set ...
endif


.PHONY : target
target : \
		cipher.elf \
		cipher.lst \
		$(LSTS)

.PHONY : target1
target1 : \
		scenario1.elf \
		scenario1.lst \
		$(LSTS)

.PHONY : target2 
target2 : \
		scenario2.elf \
		scenario2.lst \
		$(LSTS)


cipher.elf : \
		$(OBJS) \
		main.o \
		common.o
	$(CC) $(LDFLAGS) $(addprefix $(BUILDDIR)/, $(OBJS)) \
		$(addprefix $(BUILDDIR)/, main.o) $(addprefix $(BUILDDIR)/, common.o) \
		$(LDLIBS) -o $(BUILDDIR)/$@

scenario1.elf : \
		$(OBJS) \
		scenario1.o \
		encrypt_scenario1.o \
		decrypt_scenario1.o \
		common.o
	$(CC) $(LDFLAGS) $(addprefix $(BUILDDIR)/, $(OBJS)) \
		$(addprefix $(BUILDDIR)/, scenario1.o) \
		$(addprefix $(BUILDDIR)/, encrypt_scenario1.o) \
		$(addprefix $(BUILDDIR)/, decrypt_scenario1.o) \
		$(addprefix $(BUILDDIR)/, common.o) $(LDLIBS) -o $(BUILDDIR)/$@

scenario2.elf : \
		$(OBJS) \
		scenario2.o \
		encrypt_scenario2.o \
		decrypt_scenario2.o \
		round_keys.o \
		common.o
	$(CC) $(LDFLAGS) $(addprefix $(BUILDDIR)/, $(OBJS)) \
		$(addprefix $(BUILDDIR)/, scenario2.o) \
		$(addprefix $(BUILDDIR)/, encrypt_scenario2.o) \
		$(addprefix $(BUILDDIR)/, decrypt_scenario2.o) \
		$(addprefix $(BUILDDIR)/, round_keys.o) \
		$(addprefix $(BUILDDIR)/, common.o) $(LDLIBS) -o $(BUILDDIR)/$@


cipher.bin : $(BUILDDIR)/cipher.elf
	$(OBJCOPY) -O binary $< $@

scenario1.bin : $(BUILDDIR)/scenario1.elf
	$(OBJCOPY) -O binary $< $@

scenario2.bin : $(BUILDDIR)/scenario2.elf
	$(OBJCOPY) -O binary $< $@


%.o : \
		%.c \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h \
		$(SOURCEDIR)/data_types.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@


main.o : \
		$(COMMONSOURCEDIR)/main.c \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

common.o : \
		$(COMMONSOURCEDIR)/common.c \
		$(COMMONSOURCEDIR)/common.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/test_vectors.h \
		$(SOURCEDIR)/constants.h 
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@


scenario1.o : \
		$(SCENARIO1SOURCEDIR)/scenario1.c \
		$(SCENARIO1SOURCEDIR)/scenario1.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

encrypt_scenario1.o : \
		$(SCENARIO1SOURCEDIR)/encrypt_scenario1.c \
		$(SCENARIO1SOURCEDIR)/scenario1.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

decrypt_scenario1.o : \
		$(SCENARIO1SOURCEDIR)/decrypt_scenario1.c \
		$(SCENARIO1SOURCEDIR)/scenario1.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

scenario2.o : \
		$(SCENARIO2SOURCEDIR)/scenario2.c \
		$(SCENARIO2SOURCEDIR)/scenario2.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

encrypt_scenario2.o : \
		$(SCENARIO2SOURCEDIR)/encrypt_scenario2.c \
		$(SCENARIO2SOURCEDIR)/scenario2.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

decrypt_scenario2.o : \
		$(SCENARIO2SOURCEDIR)/decrypt_scenario2.c \
		$(SCENARIO2SOURCEDIR)/scenario2.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

round_keys.o : \
		$(SCENARIO2SOURCEDIR)/round_keys.c \
		$(SCENARIO2SOURCEDIR)/round_keys.h \
		$(SCENARIO2SOURCEDIR)/scenario2.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@


cipher.lst : cipher.elf
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@

scenario1.lst : scenario1.elf
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@

scenario2.lst : scenario2.elf
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@

%.lst : %.o
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@


clean :
	@echo $(DELIMITER) Begin cleaning: $(CIPHERNAME) $(DELIMITER)
	rm -f *~
	rm -f $(SOURCEDIR)/*~
	rm -f $(COMMONSOURCEDIR)/*~

	rm -f $(BUILDDIR)/cipher.elf
	rm -f $(BUILDDIR)/cipher.bin
	rm -f $(BUILDDIR)/cipher.lst

	rm -f $(BUILDDIR)/scenario1.elf
	rm -f $(BUILDDIR)/scenario1.bin
	rm -f $(BUILDDIR)/scenario1.lst

	rm -f $(BUILDDIR)/scenario2.elf
	rm -f $(BUILDDIR)/scenario2.bin
	rm -f $(BUILDDIR)/scenario2.lst
	
	rm -f $(BUILDDIR)/main.o 
	rm -f $(BUILDDIR)/common.o
	
	rm -f $(addprefix $(BUILDDIR)/, $(OBJS))
	rm -f $(addprefix $(BUILDDIR)/, $(SCENARIO1ALLOBJS))
	rm -f $(addprefix $(BUILDDIR)/, $(SCENARIO2ALLOBJS))
	
	rm -f $(addprefix $(BUILDDIR)/, $(LSTS))
	rm -f $(addprefix $(BUILDDIR)/, $(SCENARIO1LSTS))
	rm -f $(addprefix $(BUILDDIR)/, $(SCENARIO2LSTS))

	rm -f $(BUILDDIR)/*.su
	rm -f $(BUILDDIR)/*.map
	@echo $(DELIMITER) End cleaning: $(CIPHERNAME) $(DELIMITER)


cleanall :
	@echo $(DELIMITER) Begin cleaning: $(CIPHERNAME) $(DELIMITER)
	rm -f *~
	rm -f $(SOURCEDIR)/*~
	rm -f $(COMMONSOURCEDIR)/*~
	rm -f $(SCENARIO1SOURCEDIR)/*~
	rm -f $(SCENARIO2SOURCEDIR)/*~
	rm -f $(BUILDDIR)/*
	@echo $(DELIMITER) End cleaning: $(CIPHERNAME) $(DELIMITER)


help:
	@echo ""
	@echo -n "Call this makefile from a cipher source directory or build "
	@echo 		"directory to build the given cipher:"
	@echo -n "	make -f ./../../../common/cipher.mk "
	@echo -n		"[ARCHITECTURE=[AVR|MSP|ARM|PC]] [DEBUG=[0|1|3|7]] "
	@echo -n		"[MEASURE_CYCLE_COUNT=[0|1]] [SCENARIO=[0|1|2]] " 
	@echo -n		"[COMPILER_OPTIONS='...'] [all|clean|cleanall|help]"
	@echo ""
	@echo ""
	@echo " 	Examples: "
	@echo "		make -f ./../../../common/cipher.mk"
	@echo -n "		make -f ./../../../common/cipher.mk ARCHITECTURE=PC "
	@echo 			"DEBUG=1 SCENARIO=0"
	@echo "		make -f ./../../../common/cipher.mk clean"
	@echo ""
