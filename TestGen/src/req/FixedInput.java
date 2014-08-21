package req;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import com.galois.hacrypto.Util;

public class FixedInput implements Input {

	private byte[] value;
	private String name;
	
	public FixedInput(byte[] value, String name){
		this.value = value;
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
		sb.append(Util.byteArraytoHexString(value));
		return new SimpleEntry<String, Object>(sb.toString(), value);
	}

}
