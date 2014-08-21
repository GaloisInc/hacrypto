package req;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;


public class LengthInput implements Input {
	private String name;
	private int lengthOf;
	private Req req;
	
	public LengthInput(String name, int lengthof, Req req) {
		this.name = name;
		this.lengthOf = lengthof;
		this.req = req;
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
		int l = req.getInput(lengthOf).getInputLength().peekLength();
		sb.append(l);
		return new SimpleEntry<String, byte[]>(sb.toString(), new byte[0]);
	}
}
