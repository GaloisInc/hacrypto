package com.galois.hacrypto.req.input;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.galois.hacrypto.req.length.InputLength;
import com.galois.hacrypto.test.Util;

public class FixedInput implements Input {

	private byte[] value;
	private String name;
	private int number;
	private int ct;
	private int increment;
	
	public FixedInput(byte[] value, String name, int number){
		this(value, name, number, 0);
	}
	
	public FixedInput(int length, String name, int number){
		this(length, name, number, 0);
	}
	
	public FixedInput(byte[] value, String name, int number, int increment){
		this.value = value;
		this.name = name;
		this.number = number;
		this.increment = increment;
	}
	
	public FixedInput(int length, String name, int number, int increment){
		this.value = new byte[length/8];
		Util.rand.nextBytes(value);
		this.name = name;
		this.number = number;
		this.increment = increment;
	}
	
	@Override
	public boolean hasNextInput() {
		return(number == 0 || ct >= number);
	}

	@Override
	public InputLength getInputLength() {
		return null;
	}

	@Override
	public Entry<String, byte[]> toReqString() {
		StringBuilder sb = new StringBuilder(name);
		sb.append(" = ");
		sb.append(Util.byteArraytoHexString(value));
		for(int i=0; i<increment; i++){
			Util.increment(value);
		}
		ct++;
		return new SimpleEntry<String, byte[]>(sb.toString(), value);
	}

}
