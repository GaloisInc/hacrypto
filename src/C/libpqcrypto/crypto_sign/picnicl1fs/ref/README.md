# Picnic reference implementation
This is the reference implementation of the Picnic signature scheme. 

The public API surface is in picnic.h.

## Build instructions
This version only supports Linux (tested in Ubuntu 16.04 and the Windows
Subsystem for Linux)

Type `make` to build the picnic library and the example program `example`. 
Type `make clean; make nistkat` to build a program that generates known-answer tests
for NIST. 

