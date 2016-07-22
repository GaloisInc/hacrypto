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
ExecStep $xv_path/bin/xsim Test_aes_AESEncrypt_295_behav -key {Behavioral:sim_1:Functional:Test_aes_AESEncrypt_295} -tclbatch Test_aes_AESEncrypt_295.tcl -log simulate.log
