#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu> and 
# Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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
# ARM make file variables 
#


# System directory code path
SYSTEM_DIR := ../../../../../common/arm

CC := arm-none-eabi-gcc
OBJDUMP := arm-none-eabi-objdump
OBJCOPY := arm-none-eabi-objcopy
BOSSAC := bossac

ARM_SERIAL_TERMINAL := $(SYSTEM_DIR)/arm_serial_terminal.py

PORT := ttyACM0
DEVICE := /dev/$(PORT)

CFLAGS := \
	-mcpu=cortex-m3 \
	-D__SAM3X8E__ \
	-march=armv7-m \
	-mthumb \
	-g \
	-fdata-sections \
	-ffunction-sections \
	-fstack-usage \
	-Wcast-align \
	-Wsign-compare \
	-Waggregate-return \
	-Wunused \
	-Wfatal-errors \
	-Wa,-mimplicit-it=thumb \
	-Wa,-EL \
	-fno-exceptions \
	-I$(SYSTEM_DIR)/include

LDFLAGS := \
    -mcpu=cortex-m3 \
    -march=armv7-m \
    -mthumb \
    -T$(SYSTEM_DIR)/flash.ld \
	-L$(SYSTEM_DIR) \
	-Wl,--gc-sections \
	-Wl,--relax \
    -Wl,--entry=Reset_Handler

LDLIBS := -lsam3x

OBJDUMPFLAGS := -dSt


# Upload the program to the board. Should be invoked as: 
#	make -f ./../../../common/cipher.mk ARCHITECTURE=ARM upload-cipher
.PHONY : upload-cipher
upload-cipher : cipher.bin
	@# Communicate with the board @1200 Bd resets everything
	@stty -F $(DEVICE) cs8 1200 hupcl
	@# Use bossac to load program in flash
	@$(BOSSAC) --port=$(PORT) -U false -e -w -b $< -R #-d -i -v

# Upload the program to the board. Should be invoked as: 
#	make -f ./../../../common/cipher.mk ARCHITECTURE=ARM upload-scenario1
.PHONY : upload-scenario1
upload-scenario1 : scenario1.bin
	@# Communicate with the board @1200 Bd resets everything
	@stty -F $(DEVICE) cs8 1200 hupcl
	@# Use bossac to load program in flash
	@$(BOSSAC) --port=$(PORT) -U false -e -w -b $< -R #-d -i -v

# Upload the program to the board. Should be invoked as: 
#	make -f ./../../../common/cipher.mk ARCHITECTURE=ARM upload-scenario2
.PHONY : upload-scenario2
upload-scenario2 : scenario2.bin
	@# Communicate with the board @1200 Bd resets everything
	@stty -F $(DEVICE) cs8 1200 hupcl
	@# Use bossac to load program in flash
	@$(BOSSAC) --port=$(PORT) -U false -e -w -b $< -R #-d -i -v

# Run the program stored in the flash memory of the board. Should be invoked as: 
#	make -f ./../../../common/cipher.mk ARCHITECTURE=ARM run
# Note that the binary should be uploaded first.
.PHONY : run
run :
	./$(ARM_SERIAL_TERMINAL) $(DEVICE)
