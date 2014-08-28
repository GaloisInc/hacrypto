package com.galois.hacrypto.req.length;

/**
 * Object containing the length of an input. This specifies two types of
 * lengths: The number of tests that can be generated using this input, and the
 * actual length in bits of the input
 * 
 * @author jdodds
 * 
 */
public interface InputLength {
	/**
	 * @return If there are more test cases that can be generated using this test
	 */
	public boolean hasNextLength();

	/**
	 * @return a length without advancing the counter
	 */
	public int peekLength();

	/**
	 * @return a length, advancing the counter
	 */
	public int getLength();

}
