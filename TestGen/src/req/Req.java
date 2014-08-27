package req;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Queue;

import com.galois.hacrypto.Util;

/**
 * Creates a .req and .rsp file given a test definition file
 * 
 * @author jdodds
 * 
 */
public class Req {
	private List<Queue<Input>> inputs;
	private int currentOutput = 0;
	private Properties p;

	public Input getInput(int n) {
		return inputs.get(n).peek();
	}

	/**
	 * We say there is no next test if any of the inputs has no more tests. This
	 * function will advance to the next input if there is a multiple input and
	 * the one at the front of the queue has run out
	 * 
	 * @return 
	 */
	private boolean hasNextTest() {
		for (int i = 0; i < inputs.size(); i++) {
			Queue<Input> inputq = inputs.get(i);
			while (inputq.peek() != null && !inputq.peek().hasNextInput()) {
				inputq.poll();
				String outputEndName = "output" + currentOutput + "_end";
				if (p.containsKey(outputEndName)) {
					if (Integer.parseInt(p.getProperty(outputEndName).trim()) == i) {
						currentOutput++;
					}
				}
			}
			if (inputq.peek() == null) {
				return false;
			}
		}
		return true;
	}

	// this is destructive because hasNextTest is
	/**
	 * Create a NIST .req and .rsp string representing this test
	 * @return a pair of .req and .rsp files. If no output is given the files will be the same
	 */
	public Entry<String, String> creatReqRsp() {
		StringBuilder reqSb = new StringBuilder();
		StringBuilder rspSb = new StringBuilder();
		while (this.hasNextTest()) {
			List<byte[]> args = new ArrayList<byte[]>();
			for (Queue<Input> input : inputs) {
				Entry<String, byte[]> e = input.peek().toReqString();
				args.add(e.getValue());
				reqSb.append(e.getKey());
				rspSb.append(e.getKey());
				reqSb.append("\n");
				rspSb.append("\n");
			}
			if (p.containsKey("output" + currentOutput + "_name")) {
				int outputArgs = Integer.parseInt(p.getProperty(
						"output" + currentOutput + "_args", "0").trim());
				int[] argOrder = new int[outputArgs];
				for (int i = 0; i < outputArgs; i++) {
					argOrder[i] = Integer.parseInt(p.getProperty(
							"output" + currentOutput + "_arg" + i, "0").trim());
				}
				String func = p.getProperty("output" + currentOutput
						+ "_function", "output" + currentOutput
						+ "_function not given");
				rspSb.append(p.getProperty("output" + currentOutput + "_name")
						.trim());
				rspSb.append(" = ");
				rspSb.append(Util.byteArraytoHexString(Output.getOutput(func,
						args, argOrder)));
				rspSb.append("\n");
			}
			reqSb.append("\n");
			rspSb.append("\n");
		}
		return new SimpleEntry<String, String>(reqSb.toString(),
				rspSb.toString());
	}

	private int getIntProperty(String suffix, int inputno) {
		String s = getStringProperty(suffix, inputno);
		if (s == null) {
			return 0;
		}
		return Integer.parseInt(s);
	}

	private String getStringProperty(String suffix, int inputno) {
		return getStringProperty(suffix, inputno, null);

	}

	private String getStringProperty(String suffix, int inputno, String def) {
		String s = p.getProperty("input" + inputno + "_" + suffix, def);
		if (s == null) {
			return null;
		}
		return s.trim();
	}

	private boolean containsProperty(String suffix, int inputno) {
		return p.containsKey("input" + inputno + "_" + suffix);
	}

	private void addInput(int index, Input input) {
		if (index >= inputs.size() || inputs.get(index) == null) {
			Queue<Input> q = new LinkedList<>();
			inputs.add(index, q);
		}
		inputs.get(index).add(input);
	}

	/**
	 * Create a Req object from a req file. The form of the req is given in the readme file for this project
	 *  
	 * @param fileName
	 * @throws IOException
	 */
	public Req(String fileName) throws IOException {
		p = new Properties();
		FileInputStream in = new FileInputStream(fileName);
		p.load(in);

		int inputCt = Integer.parseInt(p.getProperty("inputs"));
		inputs = new ArrayList<Queue<Input>>(inputCt);

		for (int i = 0; i < inputCt; i++) {
			int mult = 1;
			if (containsProperty("mult", i)) {
				mult = getIntProperty("mult", i);
			}

			for (int m = 0; m < mult; m++) {
				String suff2;
				if (mult == 1) {
					suff2 = "";
				} else {
					suff2 = "" + m;
				}

				String inputName = getStringProperty("name" + suff2, i);
				String inputType = getStringProperty("type" + suff2, i,
						"no type available: input" + i + "_type" + suff2);

				switch (inputType.toUpperCase()) {

				case "LENGTH":
					int lengthOf = getIntProperty("lengthof" + suff2, i);
					addInput(i, new LengthInput(inputName, lengthOf, this));
					break;

				case "RANDOM": {
					int minLength = getIntProperty("minlength" + suff2, i);
					int maxLength = getIntProperty("maxlength" + suff2, i);
					int ct = getIntProperty("ct" + suff2, i);
					InputLength il = new RandomInputLength(minLength,
							maxLength, ct);
					addInput(i, new RandomInput(inputName, il));
				}
					break;

				case "INCREASE": {
					int minLength = getIntProperty("minlength" + suff2, i);
					int maxLength = getIntProperty("maxlength" + suff2, i);
					int stepSize = getIntProperty("stepsize" + suff2, i);
					InputLength il = new StepInputLength(minLength, maxLength,
							stepSize);
					addInput(i, new RandomInput(inputName, il));
				}
					break;

				case "COUNT": {
					int min = getIntProperty("min" + suff2, i);
					int max = getIntProperty("max" + suff2, i);
					addInput(i, new CountInput(inputName, min, max));
				}
					break;
					
				case "RNGV" : {
					addInput(i, new RngVInput(getIntProperty("length" + suff2, i)));
					break;
				}
				
				case "FIXED" : {
					int number = getIntProperty("number" + suff2, i);
					int increment = getIntProperty("increment", i);
					if(containsProperty("value" + suff2, i)){
						String value = getStringProperty("value" + suff2, i);
						addInput(i, new FixedInput(Util.hexStringToByteArray(value), inputName, number, increment));
					}
					else{
						int length = getIntProperty("length" + suff2, i);
						addInput(i, new FixedInput(length, inputName, number, increment));
					}
					break;
				}


				default:
					throw new RuntimeException("Unknown test type: "
							+ inputType);
				}
			}
		}

	}

	public static void main(String args[]) throws IOException {
		Req r = new Req("test_defs/CBCMMT128");
		System.out.println(r.creatReqRsp().getValue());
	}
}
