package com.galois.hacrypto.req.input;

import java.nio.ByteBuffer;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.galois.hacrypto.req.length.InputLength;

/**
 * Input that gives an increasing count
 * 
 * @author jdodds
 */
public class CountInput extends AbstractInput {

	private int min;
	private int max;
	private int ct;

	/**
	 * @param name
	 *            Name of the input: will be printed before the input in the
	 *            .req file
	 * @param min
	 *            where to start counting
	 * @param max
	 *            counting is modulo the max. If max is 0 counting will continue
	 *            indefinitely
	 * @param show 
	 * 			  YES, NO or ONCE as this input should appear in the output file for
	 *            every test, no tests, or once at the top
	 */
	public CountInput(String name, int min, int max, int show) {
		super(name, show);
		this.max = max;
		this.min = this.ct = min;
	}

	@Override
	public boolean hasNextInput() {
		return true;
	}

	@Override
	public InputLength getInputLength() {
		return null;
	}

	@Override
	public Entry<String, byte[]> toReqString() {
		StringBuilder sb = new StringBuilder(name);
		sb.append(" = ");
		if (max >= 0 && ct > max) {
			ct = this.min;
		}
		sb.append(ct++);
		return new SimpleEntry<String, byte[]>(sb.toString(), ByteBuffer
				.allocate(4).putInt(ct - 1).array());
	}

}
