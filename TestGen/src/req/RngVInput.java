package req;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.galois.hacrypto.Util;

public class RngVInput implements Input {

	private InputLength il;
	private byte[] value;
	int byteno;
	String name = "V";
	
	/**
	 * @param length in bits
	 * @param ct number of tests to generate
	 */
	public RngVInput(int length) {
		this.il = new FixedInputLength(length);
		this.value = new byte[length/8];
	}
	
	public RngVInput(String name, int length) {
		this.il = new FixedInputLength(length);
		this.value = new byte[length/8];
		this.name = name;
	}

	@Override
	public boolean hasNextInput() {
		return value[value.length-1] != -1;
	}

	@Override
	public InputLength getInputLength() {
		return il;
	}

	@Override
	public Entry<String, byte[]> toReqString() {
		StringBuilder sb = new StringBuilder(name);
		sb.append(" = ");

		
		if(value[byteno]==-1){
			byteno++;
		}
		if(value[byteno]==0){
			value[byteno] = -128;
		}
		else{
		
		value[byteno] = (byte) (value[byteno]/2);
		}
		sb.append(Util.byteArraytoHexString(value));

		return new SimpleEntry<String, byte[]>(sb.toString(), value);
	}

}
