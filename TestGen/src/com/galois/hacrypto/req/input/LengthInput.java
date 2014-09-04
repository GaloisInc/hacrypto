package com.galois.hacrypto.req.input;

import java.nio.ByteBuffer;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.galois.hacrypto.req.Req;
import com.galois.hacrypto.req.length.InputLength;

/**
 * Input that gives the length of another input
 * 
 * @author jdodds
 * 
 */
public class LengthInput extends AbstractInput {
	private int lengthOf;
	private Req req;
	private boolean isBytes = false;

	/**
	 * @param name
	 *            Name of this input. Will appear before the value of the input
	 *            in the req string
	 * @param lengthof
	 *            number of the input that this input gives the length of
	 * @param req
	 *            the parent req. This is the req that the lengthof argument
	 *            points into
	 * @param units can be byte or bytes. Any other value will result in the length being printed in bits
	 * @param show 
	 * 			  YES, NO or ONCE as this input should appear in the output file for
	 *            every test, no tests, or once at the top
	 */
	public LengthInput(String name, int lengthof, Req req, String units, int show) {
		super(name, show);
		this.lengthOf = lengthof;
		this.req = req;
		if (units != null
				&& (units.toUpperCase().equals("BYTES") || units.toUpperCase()
						.equals("BYTE"))) {
			isBytes = true;
		}
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
		int l = req.getInput(lengthOf).getInputLength().peekLength();
		if (isBytes) {
			l = l / 8;
		}

		sb.append(l);

		return new SimpleEntry<String, byte[]>(sb.toString(), ByteBuffer
				.allocate(4).putInt(l).array());
	}
}
