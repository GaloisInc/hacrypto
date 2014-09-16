package com.galois.hacrypto.req.input;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.galois.hacrypto.req.Req;
import com.galois.hacrypto.req.length.InputLength;
import com.galois.hacrypto.test.Util;

/**
 * An input that prints the same value as some other input
 * 
 * @author jdodds
 * 
 */
public class CopyInput extends AbstractInput {

	private int copyOf;
	private Req req;

	/**
	 * @param name
	 *            The name of the input
	 * @param copyOf
	 *            int identifier of the input that this input is a copy of
	 * @param req
	 *            the req containing this and the input to be copied
	 * @param show 
	 * 			  YES, NO or ONCE as this input should appear in the output file for
	 *            every test, no tests, or once at the top
	 */
	public CopyInput(String name, int copyOf, Req req, int show) {
		super(name, show);
		this.req = req;
		this.copyOf = copyOf;
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
		sb.append(Util.byteArrayToHexString(req.getPrevValue(copyOf)));
		return new SimpleEntry<String, byte[]>(sb.toString(),
				req.getPrevValue(copyOf));
	}
}
