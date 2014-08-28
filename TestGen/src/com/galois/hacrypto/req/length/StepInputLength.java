package com.galois.hacrypto.req.length;

public class StepInputLength implements InputLength {

	private int stepSize;
	private int minLength;
	private int maxLength;
	int currentCt=0;

	public StepInputLength(int minLength, int maxLength, int stepSize) {
		this.maxLength = maxLength;
		this.minLength = minLength;
		this.stepSize = stepSize;
	}

	@Override
	public boolean hasNextLength() {
		return minLength + (stepSize * currentCt) <= maxLength;
	}

	@Override
	public int peekLength() {
		return minLength + (currentCt * stepSize);
	}

	@Override
	public int getLength() {
		int ret = peekLength();
		currentCt ++;
		return ret;
	}

}
