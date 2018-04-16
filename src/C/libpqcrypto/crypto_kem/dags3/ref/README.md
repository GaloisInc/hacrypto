# DAGS: Key Encapsulation using Dyadic GS Codes

Implementation for the Key Encapsulation system using Dyadic GS Codes paper ref (https://eprint.iacr.org/2017/1037.pdf)

The instruction is applied for Linux/Ubuntu/Debian. 

### INSTALLATION 

You will need to Keccak libraries have the software run. 

```bash
#!/usr/bash
sudo apt-get install xsltproc
git clone https://github.com/gvanas/KeccakCodePackage
cd KeccakCodePackage/ 
make generic64/libkeccak.a
cd bin/generic64/
sudo mkdir /usr/local/include/keccak/
sudo cp libkeccak.a.headers/* /usr/local/include/keccak/
sudo cp libkeccak.a /usr/local/lib/
echo "DONE"
``` 

Although we leave keccak in the build, but it might be obsolete someday so we recommend you do the instruction above to have newest Keccak library. 


### BUILD

To build the binary, just run:

```bash

make clean 
make 

```


### RUN 

To run, `./PQCgenKAT_kem` 
