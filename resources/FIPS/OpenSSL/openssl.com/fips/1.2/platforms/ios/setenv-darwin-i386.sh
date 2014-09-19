#
# setenv-darwin-i386.sh
#

SYSTEM="Darwin"
MACHINE="i386"
KERNEL_BITS=32

export SYSTEM
export MACHINE
export KERNEL_BITS

# adjust the path to ensure we always get the correct tools
export PATH="`pwd`"/iOS:$PATH
