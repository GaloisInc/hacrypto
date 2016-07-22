//-------------------------------------------------------------------------------------------------
//  Written by Arash Saifhashemi, saifhash@usc.edu
//  SystemVerilogCSP: Channel interface for modeling channel based asynchronous circuits
//  USC Asynchronous CAD/VLSI Group
//  University of Southern California
//  http://async.usc.edu
//-------------------------------------------------------------------------------------------------
`timescale 1ns/1fs
// uncomment the following line to enable stall calculation and display
//`define displayStalls 1
//uncomment the following line for automatic deadlock detection
`define detectDeadlock 1
`define defaultWatchDogTime 100ns

package SystemVerilogCSP;
  typedef enum {idle, r_pend, s_pend, s12m_pend} ChannleStatus;
  typedef enum {P2PhaseBD, P4PhaseBD, P1of2, P1of4} ChannelProtocol;
  typedef enum {ZERO, ONE, NUTRAL} V1of2;
  typedef logic [3:0] Channel1Of4 ;
endpackage : SystemVerilogCSP
//-------------------------------------------------------------------------------------------------
import SystemVerilogCSP::*;
//-------------------------------------------------------------------------------------------------
interface Channel;
  parameter SHARED = 0;
  parameter WIDTH = 8;
  parameter ChannelProtocol hsProtocol = P2PhaseBD;
  parameter NUMBER_OF_RECEIVERS = 1;
`ifdef detectDeadlock
  time lastSendEvent = 0;
  time lastReceiveEvent = 0;
`endif
  ChannleStatus status = idle;    //Stores the status of a channel
  logic req=0, ack=0, e=1;             //Handshaking signals
  logic oReq, oAck, oE;               //Shadow handshaking signals

  logic hsSenderPhase=1;
  logic hsReceiverPhase=1;

  logic [WIDTH-1:0] data=0, data0=0,data1=0;         //Actual data being communicated  
  logic [WIDTH-1:0] oData, oData0,oData1;         //Actual data being communicated  
  logic _RESET = 1;

  Channel1Of4 [((WIDTH+1)/2)-1:0] data_1of4;
  integer receiveCounter =0;
  semaphore receivers =  new(0);  //Mehrdad: It seems this semaphore is not in use
  genvar i;
  
  always @oReq		req = oReq;
  always @oAck		ack = oAck;
  always @oData 	data = oData;
  always @oData0	data0 = oData0;
  always @oData1	data1 = oData1;
  always @oE ack=~oE;
  always @ack e = ~ack;
  //always @_RESET ack=~RESET;

`ifdef detectDeadlock
  always  
  begin
      # (`defaultWatchDogTime);
     fork
      if(status==s_pend) 
      begin
          if(($time - lastSendEvent) > `defaultWatchDogTime)
          begin
            #(lastSendEvent - ($time - 2*`defaultWatchDogTime)) $display("###Deadlock Detected on %m @ %t",lastSendEvent);
            wait(0);
          end
    end
    if(status==r_pend)
    begin
          if(($time - lastReceiveEvent) > `defaultWatchDogTime)
          begin
            #(lastReceiveEvent - ($time - 2*`defaultWatchDogTime)) $display("###Deadlock Detected on %m @ %t",lastReceiveEvent);
          wait(0);
          end
    end
    join
  end
`endif
//-------------------------------------------------------------------------------------------------    
function Channel1Of4 [((WIDTH+1)/2)-1:0] SingleRailToP1of4 ();
	for (integer i = 0 ; i <= WIDTH-2 ; i+=2)
	begin
		case ({data [i+1], data[i]})
			2'b00: data_1of4[i/2] = 4'b0001;
			2'b01: data_1of4[i/2] = 4'b0010;
			2'b10: data_1of4[i/2] = 4'b0100;
			2'b11: data_1of4[i/2] = 4'b1000;
		endcase
	end
	SingleRailToP1of4 = data_1of4;
endfunction
//-------------------------------------------------------------------------------------------------    
function  logic [WIDTH-1:0] P1of4ToSingleRail ();
	for (integer i = 0 ; i <= WIDTH-2 ; i+=2)
	begin
		case ( data_1of4 [i/2])
			4'b0001: data[i/2] = 2'b00;
			4'b0010: data[i/2] = 2'b01;
			4'b0100: data[i/2] = 2'b10;
			4'b1000: data[i/2] = 2'b11;
		endcase
	end
	P1of4ToSingleRail = data_1of4;
endfunction
//-------------------------------------------------------------------------------------------------    
//Communication Action Tasks
//-------------------------------------------------------------------------------------------------
task Send (input logic[WIDTH-1:0] d);
`ifdef displayStalls
time start,stall;
start = $time;
`endif
`ifdef detectDeadlock
lastSendEvent = $time;
`endif
	if(hsProtocol == P4PhaseBD || hsProtocol == P1of2)
	begin
                data = d;
		data0 = ~d;
		data1 = d;
		req = 1;
		status = s_pend;                //Set the status to s_pend before wait
		wait (ack == 1 );
		data0 = 0;
		data1 = 0;
		req = 0;
		wait (ack == 0 );
		status = idle;
	end
	else if (hsProtocol == P2PhaseBD )
	begin
		data = d;
		data0 =  ~d;
		req = hsSenderPhase;
		status = s_pend;                //Set the status to s_pend before wait
		wait (ack == hsSenderPhase );
		status = idle;
		hsSenderPhase = ~hsSenderPhase;
	end
`ifdef displayStalls
stall = $time - start;
if(stall != 0) $display("### %m Stalled(%d) @ %t",stall,$time);
`endif
endtask
//-------------------------------------------------------------------------------------------------
task SplitSend (input logic[WIDTH-1:0] d, input integer part, input integer FL = 0);
	case(hsProtocol)
		P1of2:	P4PhaseBD:
		begin 
			case (part)
				1: begin
					data <= #FL d;
					data0 <= #FL ~d;
					data1 <= #FL d;
					req = 1;
					status = s_pend;                //Set the status to s_pend before wait
				end
				2: begin
					wait (ack == 1 );
				end
				3: begin
					data0 = 0;
					data1 = 0;
					req = 0;
				end
				4: begin
					wait (ack == 0 );
					status = idle;
				end
			endcase
		end //P1of2, P4PhaseBD
		P2PhaseBD:
		begin
			case (part)
				1: begin
					data = d;   //Mehrdad: Do we need to have #FL  here is well?
					data0 =  ~d;
					req = hsSenderPhase;
					status = s_pend;                //Set the status to s_pend before wait
				end
				2: begin
					wait (ack == hsSenderPhase );
					status = idle;
					hsSenderPhase = ~hsSenderPhase;
				end
			endcase
		end	//P2PhaseBD
	endcase
endtask
//-------------------------------------------------------------------------------------------------
task Receive (output logic[WIDTH-1:0] d);
`ifdef displayStalls
time start,stall;
start = $time;
`endif
`ifdef detectDeadlock
lastReceiveEvent = $time;
`endif
	if (hsProtocol==P4PhaseBD || hsProtocol == P1of2)
	begin
		status = r_pend;
		if (hsProtocol == P1of2 )
			wait ( (&(data0 | data1)==1) );
		else
		  begin
			 wait (req == 1 );
			 if (SHARED)
			     req = 'z; // Inhibit other receivers from receiving
			end
		d = data1;
		data = data1;
		//If the last receiver:
		if (receiveCounter == NUMBER_OF_RECEIVERS-1)
		begin
			ack = 1; 
			if (hsProtocol == P1of2)
				wait ( (|(data0 | data1)==0) );
			else
				wait (req == 0 );
			ack = 0;
			status = idle; 
			receiveCounter=0;
			#0;						//Release the control to other processes
		end
		else // If not the last receiver wait for other receivers to finish
		begin
			status = s12m_pend;
			receiveCounter++; 
			wait (receiveCounter ==0);	//Wait for other Receivers to finish.					
		end        
	end //P4PhaseBD or P1of2
	
	else  if (hsProtocol == P2PhaseBD)
	begin
		status = r_pend;                //Set the status to r_pend before wait
		wait (req == hsReceiverPhase );
	  if (SHARED)
		  req = 'z; // Inhibit other receivers from receiving
		d = data;    
		//Is this the last receiver? 
		if (receiveCounter == NUMBER_OF_RECEIVERS-1)
        begin
			ack = hsReceiverPhase; 
			status = idle;
			receiveCounter=0;
			#0;						//Release the control to other processes
			hsReceiverPhase=~hsReceiverPhase;
        end
		else  //Wait for all other receivers to finish receiving
        begin
			status = s12m_pend; 
			receiveCounter++; 
			wait (receiveCounter ==0 );
			#0;						//Release the control to other processes
        end
  end
`ifdef displayStalls
stall = $time - start;
if(stall != 0) $display("### %m Stalled(%d) @ %t",stall,$time);
`endif
endtask
//-------------------------------------------------------------------------------------------------
task SplitReceive (output logic[WIDTH-1:0] d, input integer part);
	case(hsProtocol)
		P1of2:
		P4PhaseBD:
		begin 
			case (part)
				1: begin
					status = r_pend;
					if (hsProtocol == P1of2 )
						wait ( (&(data0 | data1)==1) );
					else
						wait (req == 1 );
				end
				2: begin
					d = data1;
					ack = 1;  
				end
				3: begin
					if (hsProtocol == P1of2 )
						wait ( (|(data0 | data1)==0) );
					else
						wait (req == 0 );
				end 
				4:begin
					ack = 0;
					status = idle;
				end
			endcase
		end //P1of2 or P4PhaseBD
		P2PhaseBD: begin
			case (part)
				1: begin
					status = r_pend;                //Set the status to r_pend before wait
					wait (req == hsReceiverPhase );
					d = data;    
				end
				2: begin
					ack = hsReceiverPhase; 
					status = idle;  
					hsReceiverPhase = ~ hsReceiverPhase;
				end
			endcase
		end	//P2PhaseBD
	endcase
endtask
//-------------------------------------------------------------------------------------------------
task Peek (output logic[WIDTH-1:0] d);
  wait (status != idle && status != r_pend );
  d = data; 
endtask
//-------------------------------------------------------------------------------------------------
//probe_wait_input: used on an input/output port. wait until other party starts communication
task Probe_wait_input () ;
  wait (status != idle);
endtask
//-------------------------------------------------------------------------------------------------
endinterface: Channel
