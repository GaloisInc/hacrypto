package com.galois.hacrypto;

import javax.management.RuntimeErrorException;



public class Test {

	public enum Language {
	    C
	}
	
	public static String hexToCUChar(String st){
		StringBuilder sb = new StringBuilder();
		if(st.length() % 2 !=0){
			throw new RuntimeErrorException(null, "String " + st + " is not a valid length for a digest");
		}
		for(int i=0; i<st.length(); i=i+2){
			sb.append("0x");
			sb.append(st.charAt(i));
			sb.append(st.charAt(i+1));
			if(i+2 < st.length()){
				sb.append(", ");
			}
			if(i!=0 && (i+2)%16 == 0){
				sb.append("\n");
			}
		}
		return sb.toString();
	}
	
	public static void main(String args[]){
		System.out.println(hexToCUChar("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"));
	}
	
	
}
