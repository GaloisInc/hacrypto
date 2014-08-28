package com.galois.hacrypto.req.input;

import java.nio.ByteBuffer;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.galois.hacrypto.req.length.InputLength;
import com.galois.hacrypto.test.Util;

public class SequenceInput implements Input {

	private int[] sequence;
	private int changeEvery;
	private int repeat;
	private boolean infinite;
	private int currentCt;
	private String name;
	
	
	public SequenceInput(String name, int[] sequence, int changeevery, int repeat) {
		this.sequence = sequence;
		this.changeEvery = changeevery;
		this.repeat = repeat;
		if(repeat == 0){
			infinite = true;
		}
		else{
			infinite = false;
		}
		this.name = name;
	}

	@Override
	public boolean hasNextInput() {
		return (infinite || repeat > 0);
	}

	@Override
	public InputLength getInputLength() {
		return null;
	}

	@Override
	public Entry<String, byte[]> toReqString() {
		StringBuilder sb = new StringBuilder(name);
		sb.append(" = ");
		if(currentCt/changeEvery == sequence.length){
			currentCt = 0;
			repeat--;
		}
		int s = sequence[currentCt/changeEvery];
		sb.append(s);
		currentCt++;
		return new SimpleEntry<String, byte[]>(sb.toString(), ByteBuffer.allocate(4).putInt(s).array());
	}

}
