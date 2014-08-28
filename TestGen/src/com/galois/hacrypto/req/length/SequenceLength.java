package com.galois.hacrypto.req.length;

public class SequenceLength implements InputLength {

	private int[] sequence;
	private int changeEvery;
	private int repeat;
	private boolean infinite;
	private int currentCt;
	
	
	public SequenceLength(int[] sequence, int repeat, int changeevery) {
		this.sequence = sequence;
		this.changeEvery = changeevery;
		this.repeat = repeat;
		if(repeat == 0){
			infinite = true;
		}
		else{
			infinite = false;
		}
	}

	@Override
	public boolean hasNextLength() {
		return (infinite || repeat > 0);
	}

	@Override
	public int peekLength() {
		if(currentCt/changeEvery >= sequence.length){
			currentCt = 0;
			repeat--;
		}
		return (sequence[currentCt/changeEvery]);
	}

	@Override
	public int getLength() {
		int ret = peekLength();
		currentCt++;
		return ret;
	}

}
