package com.galois.hacrypto;

import java.util.Arrays;

/**
 * @author Joey Dodds Definition of a single Known Answer Test input
 */
public class KATInput {
	/**
	 * Defines if the test is actually composed of a repeated concatenation of
	 * the input
	 */
	public int repeat;

	/**
	 * byte representation of the input
	 */
	public byte[] bytes;

	/**
	 * how the input was given in the KAT file
	 */
	public String inputAs;

	/**
	 * Optional string that should be output as a comment above the generated
	 * test
	 */
	public String comment;

	public KATInput(int repeat, byte[] bytes, String inputAs, String comment) {
		this.repeat = repeat;
		this.bytes = bytes;
		this.inputAs = inputAs;
		this.comment = comment;
	}
	
	
	/**
	 * @param bytes
	 * @return String containing a hex representation of the byte array
	 */
	public static String byteArraytoHexString(byte[] bytes){
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X", b));
		}
		return sb.toString();
	}

	/**
	 * @param bytes
	 * @return String containing the length of the byte string followed by a
	 *         hex representation of the bytes
	 */
	public static String simpleByteString(byte[] bytes) {
		return (bytes.length + " " + byteArraytoHexString(bytes));
	}

	/**
	 * @return {@link #simpleByteString(byte[]) called on {@link #bytes}
	 */
	public String simpleInputString() {
		return simpleByteString(bytes);
	}
	
	public String toHexString(){
		return byteArraytoHexString(bytes);
	}

}
