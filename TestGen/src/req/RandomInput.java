package req;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.galois.hacrypto.Util;

public class RandomInput implements Input {

	private String name;
	private InputLength inputLength;
	public RandomInput(String name, InputLength il) {
		this.inputLength = il;
		this.name = name;
	}

	@Override
	public boolean hasNextInput() {
		return inputLength.hasNextLength();
	}

	@Override
	public InputLength getInputLength() {
		return inputLength;
	}

	@Override
	public Entry<String, byte[]> toReqString() {
		StringBuilder sb = new StringBuilder(name);
		sb.append(" = ");
		
		byte[] val = new byte[inputLength.getLength() / 8];
		Util.rand.nextBytes(val);
		if (val.length == 0) {
			sb.append("00");
		} else {
			sb.append(Util.byteArraytoHexString(val));
		}
		return new SimpleEntry<String, byte[]>(sb.toString(), val);
	}

}
