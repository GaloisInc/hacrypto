package com.galois.hacrypto.req.input;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.galois.hacrypto.req.length.InputLength;
import com.galois.hacrypto.test.Util;

public class FixedInput extends AbstractInput {

	private byte[] value;
	private int number;
	private int ct;
	private int increment;

	public FixedInput(byte[] value, String name, int number, int show) {
		this(value, name, number, 0, show);
	}

	public FixedInput(int length, String name, int number, int show) {
		this(length, name, number, 0, show);
	}

	public FixedInput(byte[] value, String name, int number, int increment, int show) {
		super(name, show);
		this.value = value;
		this.number = number;
		this.increment = increment;
	}

	public FixedInput(int length, String name, int number, int increment, int show) {
		super(name, show);
		this.value = new byte[length / 8];
		Util.rand.nextBytes(value);
		this.number = number;
		this.increment = increment;
	}

	@Override
	public boolean hasNextInput() {
		return (number == 0 || ct >= number);
	}

	@Override
	public InputLength getInputLength() {
		return null;
	}

	@Override
	public Entry<String, byte[]> toReqString() {
		StringBuilder sb = new StringBuilder(name);
		sb.append(" = ");
		for (int i = 0; i < increment; i++) {
			Util.increment(value);
		}
		sb.append(Util.byteArrayToHexString(value));
		ct++;
		return new SimpleEntry<String, byte[]>(sb.toString(), value);
	}

}
