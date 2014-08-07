package com.galois.hacrypto;

import java.util.Arrays;

public class KATInput {
	public int repeat;
	public byte[] bytes;
	public String inputAs;
	public String comment;
	
	
	public KATInput(int repeat, byte[] bytes, String inputAs, String comment) {
		this.repeat = repeat;
		this.bytes = bytes;
		this.inputAs = inputAs;
		this.comment=comment;
	}
	
	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb.append(inputAs);
		sb.append(" ");
		
		if(repeat !=1){
			sb.append("repeat ");
			sb.append(repeat);
			sb.append(" ");
		}
		
		if(inputAs.equals("string")){
			sb.append(new String(bytes));
		}
		else{
			if(!inputAs.equals("empty")){
				sb.append(Arrays.toString(bytes));
			}
		}
		return sb.toString();
	}
	
	public static String simpleByteString(byte[] bytes){
		StringBuilder sb = new StringBuilder();
		sb.append(bytes.length);
		sb.append(" ");
		for(byte b : bytes){ 
			sb.append(String.format("%02X", b));
		}
		
		return sb.toString();
	}
	
	public String simpleInputString(){
		return simpleByteString(bytes);
	}
	
}
