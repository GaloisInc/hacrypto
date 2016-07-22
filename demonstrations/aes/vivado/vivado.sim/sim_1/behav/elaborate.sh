#!/bin/bash -f
xv_path="/opt/Xilinx/Vivado/2016.2"
ExecStep()
{
"$@"
RETVAL=$?
if [ $RETVAL -ne 0 ]
then
exit $RETVAL
fi
}
ExecStep $xv_path/bin/xelab -wto 85e115b54e774da7bab3428bca05055c -m64 --debug typical --relax --mt 8 -L xil_defaultlib -L unisims_ver -L unimacro_ver -L secureip --snapshot Test_aes_AESEncrypt_295_behav xil_defaultlib.Test_aes_AESEncrypt_295 xil_defaultlib.glbl -log elaborate.log
