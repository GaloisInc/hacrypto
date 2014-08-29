package com.galois.hacrypto.req.input;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.galois.hacrypto.req.length.FixedInputLength;
import com.galois.hacrypto.req.length.InputLength;
import com.galois.hacrypto.test.Util;

/**
 * Special input for defining the "V" input of RNG tests
 * @author jdodds
 * 
 */
public class RngVInput implements Input {

	private InputLength il;
	private byte[] value;
	int byteno;
	String name = "V";

	/**
	 * Creates this object with the default name "V"
	 * @param length
	 *            in bits
	 */
	public RngVInput(int length) {
		this.il = new FixedInputLength(length);
		this.value = new byte[length / 8];
	}

	/**
	 * @param name Name of the input
	 * @param length length of the input in bits
	 */
	public RngVInput(String name, int length) {
		this.il = new FixedInputLength(length);
		this.value = new byte[length / 8];
		this.name = name;
	}

	@Override
	public boolean hasNextInput() {
		return value[value.length - 1] != -1;
	}

	@Override
	public InputLength getInputLength() {
		return il;
	}

	@Override
	public Entry<String, byte[]> toReqString() {
		StringBuilder sb = new StringBuilder(name);
		sb.append(" = ");

		if (value[byteno] == -1) {
			byteno++;
		}
		if (value[byteno] == 0) {
			value[byteno] = -128;
		} else {

			value[byteno] = (byte) (value[byteno] / 2);
		}
		sb.append(Util.byteArraytoHexString(value));

		return new SimpleEntry<String, byte[]>(sb.toString(), value);
	}

}
