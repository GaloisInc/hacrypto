package com.galois.hacrypto.req.input;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.galois.hacrypto.req.length.FixedInputLength;
import com.galois.hacrypto.req.length.InputLength;
import com.galois.hacrypto.test.Util;

public class ListInput extends AbstractInput {

	private List<byte[]> l = new ArrayList<>();
	private Iterator<byte[]> i = null;
	private boolean isInt = false;
	
	/**
	 * Construct a ListInput which holds a list of inputs and outputs them one by one
	 * this defaults to a byte array output. Use constructor {@link #ListInput(String, boolean)}
	 * to specify a list of integers
	 * @param name name of the input
	 * @param show 
	 * 			  YES, NO or ONCE as this input should appear in the output file for
	 *            every test, no tests, or once at the top
	 */
	public ListInput(String name, int show) {
		super(name, show);
	}
	
	public ListInput(String name, boolean isInt, int show){
		this(name, show);
		this.isInt = isInt;
	}
	
	public boolean isInt(){
		return isInt;
	}
	
	/**
	 * Add an input to the list of inputs
	 * @param nextIn next input to add
	 * @throws NumberFormatException if this is an integer input
	 */
	public void addInput(byte[] nextIn) throws NumberFormatException{
		if(isInt){
			throw new NumberFormatException("Tried to add a byte array to an integer list");
		}
		l.add(nextIn);
	}
	
	/**
	 * @param i integer to be added
	 */
	public void addInput(int i){
		if(!isInt){
			throw new NumberFormatException("Tried to add an int to a byte list");
		}
		l.add(Util.intToByteArray(i));
	}

	@Override
	public boolean hasNextInput() {
		if(i ==null){
			i = l.iterator();
		}
		return i.hasNext();
	}

	@Override
	public InputLength getInputLength() {
		return new FixedInputLength(l.get(0).length);
	}

	@Override
	public Entry<String, byte[]> toReqString() {
		if(i ==null){
			i = l.iterator();
		}
		byte[] res = i.next();
		String resStr;
		if(isInt){
			resStr = name + " = " + Util.byteArrayToInt(res);
		}
		else{
			resStr = name + " = " + Util.byteArrayToHexString(res);
		}
		return new SimpleEntry<String, byte[]>(resStr, res);
	}

}
