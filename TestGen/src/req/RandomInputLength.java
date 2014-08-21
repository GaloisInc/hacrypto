package req;

import com.galois.hacrypto.Util;


public class RandomInputLength implements InputLength{
	
	private int maxLength;
	private int minLength;
	private int ct;
	private int currentCt = 0;

	public RandomInputLength(int minLength, int maxLength, int ct){
		this.maxLength = maxLength;
		this.minLength = minLength;
		this.ct = ct;
	}
	
	@Override
	public boolean hasNextLength(){
		if(ct == 0){
			return true;
		}
		return currentCt < ct;
	}
	
	@Override
	public int peekLength(){
		if(minLength==maxLength){
			return minLength;
		}
		return Util.rand.nextInt(maxLength - minLength) + minLength;
	}
	
	@Override
	public int getLength(){
		int l = peekLength();
		currentCt++;
		return l;
	}
}
