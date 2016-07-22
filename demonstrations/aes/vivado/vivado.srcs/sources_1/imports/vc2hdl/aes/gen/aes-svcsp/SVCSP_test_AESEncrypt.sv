`timescale 1ns/1fs
module Test_aes_AESEncrypt_295;
Channel #(.WIDTH(128)) ZTAZTAaes_AESEncrypt_295 ();
Channel #(.WIDTH(128)) ZTAZTAkey_232 ();
Channel #(.WIDTH(128)) ZTAZTApt_233 ();
logic  [0:127] knowngood;
logic  [0:127] ZTCZTAaes_AESEncrypt_295;
logic  [0:127] ZTCZTAkey_232;
logic  [0:127] ZTCZTApt_233;
integer fd;
initial
	begin
		fd = $fopen("AESEncrypt.kat", "r");
	end
Proc_aes_AESEncrypt_295 computation (.ZTAaes_AESEncrypt_295(ZTAZTAaes_AESEncrypt_295), .ZTAkey_232(ZTAZTAkey_232), .ZTApt_233(ZTAZTApt_233));
always
	begin
		if (($fscanf(fd, "%x\n", ZTCZTAkey_232) != 2'h1))
			begin
				$stop();
			end
		if (($fscanf(fd, "%x\n", ZTCZTApt_233) != 2'h1))
			begin
				$stop();
			end
		if (($fscanf(fd, "%x\n", knowngood) != 2'h1))
			begin
				$stop();
			end
		ZTAZTAkey_232.Send(ZTCZTAkey_232);
		ZTAZTApt_233.Send(ZTCZTApt_233);
		ZTAZTAaes_AESEncrypt_295.Receive(ZTCZTAaes_AESEncrypt_295);
		//if ((knowngood !== ZTCZTAaes_AESEncrypt_295))
			//begin
				$display("%s: expected %x, got %x with inputs %x", "Test_aes_AESEncrypt_295", knowngood, ZTCZTAaes_AESEncrypt_295, {ZTCZTAkey_232, ZTCZTApt_233});
			//end
		#1 ;
	end
endmodule

