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
public class CopyInput implements Input {

	private int copyOf;
	private Req req;
	private String name;

	/**
	 * @param name
	 *            The name of the input
	 * @param copyOf
	 *            int identifier of the input that this input is a copy of
	 * @param req
	 *            the req containing this and the input to be copied
	 */
	public CopyInput(String name, int copyOf, Req req) {
		this.req = req;
		this.copyOf = copyOf;
		this.name = name;
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
		sb.append(Util.byteArraytoHexString(req.getPrevValue(copyOf)));
		return new SimpleEntry<String, byte[]>(sb.toString(),
				req.getPrevValue(copyOf));
	}

}
