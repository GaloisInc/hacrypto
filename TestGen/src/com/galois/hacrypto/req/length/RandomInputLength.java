package com.galois.hacrypto.req.length;

import com.galois.hacrypto.test.Util;

/**
 * A random length, possibly infinite input length
 * 
 * @author jdodds
 * 
 */
public class RandomInputLength implements InputLength {

	private int maxLength;
	private int minLength;
	private int ct;
	private int currentCt = 0;

	/**
	 * @param minLength
	 *            Minimum length that can be generated
	 * @param maxLength
	 *            Maximum length that can be generated. If given max is less
	 *            than min length, only minlength will be generated
	 * @param ct
	 *            number of inputs to generate. If 0 or lower is given, it will
	 *            be infinite
	 */
	public RandomInputLength(int minLength, int maxLength, int ct) {
		if (maxLength < minLength) {
			this.maxLength = minLength;
		} else {
			this.maxLength = maxLength;
		}
		this.minLength = minLength;
		this.ct = ct;
	}

	@Override
	public boolean hasNextLength() {
		if (ct <= 0) {
			return true;
		}
		return currentCt < ct;
	}

	@Override
	public int peekLength() {
		if (minLength == maxLength) {
			return minLength;
		}
		return Util.rand.nextInt(maxLength - minLength) + minLength;
	}

	@Override
	public int getLength() {
		int l = peekLength();
		currentCt++;
		return l;
	}
}
