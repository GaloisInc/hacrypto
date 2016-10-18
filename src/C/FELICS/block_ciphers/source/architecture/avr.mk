#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu> and 
# Yann Le Corre <yann.lecorre@uni.lu>
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
# AVR make file variables 
#


# Include directory code path
INCLUDE_DIR=/opt/avr_tools/simavr/simavr-1.2/simavr/sim/avr

CC := avr-gcc

CFLAGS := \
	-mmcu=atmega128 \
	-g \
	-fdata-sections \
	-ffunction-sections \
	-Wcast-align \
	-Wsign-compare \
	-Waggregate-return \
	-Wunused \
	-Wfatal-errors \
	-Wl,--gc-sections \
	-Wl,--relax \
	-Wl,--undefined=_mmcu,--section-start=.mmcu=0x910000 \
	-I$(INCLUDE_DIR)

OBJDUMP := avr-objdump

OBJDUMPFLAGS := -dSt

OBJCOPY := avr-objcopy

LDLIBS :=

LDFLAGS := $(CFLAGS)
