package req;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;


/**
 * @author jdodds
 * Input that gives an increasing count
 */
public class CountInput implements Input {

	private int min;
	private int max;
	private String name;
	private int ct;
	
	/**
	 * @param name Name of the input: will be printed before the input in the .req file
	 * @param min where to start counting
	 * @param max counting is modulo the max. If max is 0 counting will continue indefinitely 
	 */
	public CountInput(String name, int min, int max) {
		this.max = max;
		this.min = this.ct = min;
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
		if(max > 0 && ct > max){
			ct = this.min;
		}
		sb.append(ct++);
		return new SimpleEntry<String, byte[]>(sb.toString(), new byte[0]);
	}





	

}
