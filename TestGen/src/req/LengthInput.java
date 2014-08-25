package req;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;


/**
 * Input that gives the length of another input
 * @author jdodds
 *
 */
public class LengthInput implements Input {
	private String name;
	private int lengthOf;
	private Req req;
	
	/**
	 * @param name Name of this input. Will appear before the value of the input in the req string
	 * @param lengthof number of the input that this input gives the length of
	 * @param req the parent req. This is the req that the lengthof argument points into
	 */
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
