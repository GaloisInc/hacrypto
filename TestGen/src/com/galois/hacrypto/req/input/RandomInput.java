package com.galois.hacrypto.req.input;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.galois.hacrypto.req.length.InputLength;
import com.galois.hacrypto.test.Util;

/**
 * An input that is a random string of bytes
 * 
 * @author jdodds
 * 
 */
public class RandomInput implements Input {

	private String name;
	private InputLength inputLength;

	/**
	 * @param name
	 * @param il
	 *            Determines the length of each advancing input
	 */
	public RandomInput(String name, InputLength il) {
		this.inputLength = il;
		this.name = name;
	}

	@Override
	public boolean hasNextInput() {
		return inputLength.hasNextLength();
	}

	@Override
	public InputLength getInputLength() {
		return inputLength;
	}

	@Override
	public Entry<String, byte[]> toReqString() {
		StringBuilder sb = new StringBuilder(name);
		sb.append(" = ");

		byte[] val = new byte[inputLength.getLength() / 8];
		Util.rand.nextBytes(val);
		if (val.length == 0) {
			sb.append("00");
		} else {
			sb.append(Util.byteArraytoHexString(val));
		}
		return new SimpleEntry<String, byte[]>(sb.toString(), val);
	}

}
