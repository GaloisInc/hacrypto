package req;

public class FixedInputLength implements InputLength {

	private int length;
	int ct;
	int currentCt;
	
	public FixedInputLength(int length) {
		this.length = length;
	}
	
	public FixedInputLength(int length, int ct) {
		this.length = length;
		this.ct = 0;
	}

	@Override
	public boolean hasNextLength() {
		return currentCt < ct || ct ==0;
	}

	@Override
	public int peekLength() {
		return length;
	}

	@Override
	public int getLength() {
		ct++;
		return length;
	}

}
