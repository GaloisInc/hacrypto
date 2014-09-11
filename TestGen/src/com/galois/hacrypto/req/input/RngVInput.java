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
public class RngVInput extends AbstractInput {

	private InputLength il;
	private byte[] value;
	int byteno;

	/**
	 * Creates this object with the default name "V"
	 * @param length
	 *            in bits
	 * @param show 
	 * 			  YES, NO or ONCE as this input should appear in the output file for
	 *            every test, no tests, or once at the top
	 */
	public RngVInput(int length, int show) {
		this("V", length, show);
	}

	/**
	 * @param name Name of the input
	 * @param length length of the input in bits
	 * @param show 
	 * 			  YES, NO or ONCE as this input should appear in the output file for
	 *            every test, no tests, or once at the top
	 */
	public RngVInput(String name, int length, int show) {
		super(name, show);
		this.il = new FixedInputLength(length);
		this.value = new byte[length / 8];
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
		sb.append(Util.byteArrayToHexString(value));

		return new SimpleEntry<String, byte[]>(sb.toString(), value);
	}

}
