package req;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;


public class CountInput implements Input {

	private int min;
	private int max;
	private String name;
	private int ct;
	
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
	public Entry<String, Object> toReqString() {
		StringBuilder sb = new StringBuilder(name);
		sb.append(" = ");
		if(max > 0 && ct > max){
			ct = this.min;
		}
		sb.append(ct++);
		return new SimpleEntry<String, Object>(sb.toString(), new byte[0]);
	}

}
