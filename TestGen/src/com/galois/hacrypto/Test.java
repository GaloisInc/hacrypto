package com.galois.hacrypto;


public class Test {

	public static String hexToCUChar(String st){
		StringBuilder sb = new StringBuilder();
		
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
