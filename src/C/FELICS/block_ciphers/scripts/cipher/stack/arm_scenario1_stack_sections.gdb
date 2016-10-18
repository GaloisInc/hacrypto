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

# Connect to the J-Link GDB Server
target remote localhost:2331
# Select the file to debug
file scenario1.elf


# Set the maximum number fo elements of an array to be printed
set print elements 2000
# Set the threshold for suppressing display of repeated array elements
set print repeats 3000


# Set the analysed stack size in bytes in the convenience variable
set $analysed_stack_size=2000


# Reset the remote monitor
monitor reset


break BeginEncryptionKeySchedule
# Continue the program execution
continue


#
# BeginEncryptionKeySchedule breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $r13
# Set the stack content
restore ARM_scenario1_memory.mem binary $base-$analysed_stack_size


delete breakpoints 1
break EndEncryptionKeySchedule
# Continue the program execution
continue


#
# EndEncryptionKeySchedule breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


delete breakpoints 2
break BeginEncryption
# Continue the program execution
continue


# 
# BeginEncryption breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $r13
# Set the stack content
restore ARM_scenario1_memory.mem binary $base-$analysed_stack_size


delete breakpoints 3
break EndEncryption
# Continue the program execution
continue


#
# EndEncryption breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


delete breakpoints 4
break BeginDecryptionKeySchedule
# Continue the program execution
continue


# 
# BeginDecryptionKeySchedule breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $r13
# Set the stack content
restore ARM_scenario1_memory.mem binary $base-$analysed_stack_size


delete breakpoints 5
break EndDecryptionKeySchedule
# Continue the program execution
continue


#
# EndDecryptionKeySchedule breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


delete breakpoints 6
break BeginDecryption
# Continue the program execution
continue


# 
# BeginDecryption breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $r13
# Set the stack content
restore ARM_scenario1_memory.mem binary $base-$analysed_stack_size


delete breakpoints 7
break EndDecryption
# Continue the program execution
continue


# 
# EndDecryption breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


# Finish the debugging session
quit
