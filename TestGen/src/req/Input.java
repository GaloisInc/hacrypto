package req;

import java.util.Map.Entry;

public interface Input {
	public boolean hasNextInput();
	public InputLength getInputLength();
	public Entry<String, byte[]> toReqString();
}
