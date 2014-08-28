package com.galois.hacrypto.req.input;

import java.util.Map.Entry;

import com.galois.hacrypto.req.length.InputLength;

/**
 * One input in a .req file. This corresponds to an input per-test
 * 
 * @author jdodds
 * 
 */
public interface Input {
	/**
	 * @return weather or not this Input has more values. Some inputs always
	 *         have more values
	 */
	public boolean hasNextInput();

	/**
	 * @return the length corresponding to this input
	 */
	public InputLength getInputLength();

	/**
	 * creates a string of the form "name = \<value\>" for the next input. This
	 * advances the input: the next input might be different
	 * 
	 * @return A pair of the req string and the byte array value of the input if
	 *         it has one. The byte array may be empty of null
	 */
	public Entry<String, byte[]> toReqString();
}
