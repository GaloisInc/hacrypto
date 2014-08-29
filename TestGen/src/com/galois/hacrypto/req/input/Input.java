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
	 * @return whether or not this Input has more values. Some inputs always
	 *         have more values
	 */
	public boolean hasNextInput();

	/**
	 * @return the length corresponding to this input. May be null for objects
	 *         that print integers instead of byte arrays
	 */
	public InputLength getInputLength();

	/**
	 * creates a string of the form "name = value" for the next input. This
	 * advances the input: the next input might be different
	 * 
	 * @return A pair of the req string and the byte array value of the input if
	 *         it has one. The byte array may be empty of null, an empty
	 *         representation, or a byte array representation of an integer
	 */
	public Entry<String, byte[]> toReqString();
}
