package com.galois.hacrypto.req;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Queue;
import java.util.Scanner;
import java.util.Set;

import com.galois.hacrypto.req.input.CopyInput;
import com.galois.hacrypto.req.input.CountInput;
import com.galois.hacrypto.req.input.FixedInput;
import com.galois.hacrypto.req.input.Input;
import com.galois.hacrypto.req.input.LengthInput;
import com.galois.hacrypto.req.input.ListInput;
import com.galois.hacrypto.req.input.RandomInput;
import com.galois.hacrypto.req.input.RngVInput;
import com.galois.hacrypto.req.input.SequenceInput;
import com.galois.hacrypto.req.length.InputLength;
import com.galois.hacrypto.req.length.RandomInputLength;
import com.galois.hacrypto.req.length.SequenceLength;
import com.galois.hacrypto.req.length.StepInputLength;
import com.galois.hacrypto.req.output.Output;
import com.galois.hacrypto.test.Util;

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

	private ArrayList<byte[]> prevValues = new ArrayList<byte[]>();

	public byte[] getPrevValue(int n) {
		return prevValues.get(n);
	}

	public Input getInput(int n) {
		return inputs.get(n).peek();
	}

	/**
	 * We say there is no next test if any of the inputs has no more tests. This
	 * function will advance to the next input if there is a multiple input and
	 * the one at the front of the queue has run out
	 * 
	 * @return whether all inputs currently in this req can generate another
	 *         value
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
	 * 
	 * @return a pair of .req and .rsp files. If no output is given the files
	 *         will be the same
	 */
	public Entry<String, String> createReqRsp() {
		StringBuilder reqSb = new StringBuilder();
		StringBuilder rspSb = new StringBuilder();
		int inputNo = 0;
		// header comment
		if (p.getProperty("header") != null) {
			String header = p.getProperty("header");
			header = header.replace("(DATE)", (new Date()).toString());
			header = header.replace("(VERSION)", Util.VERSION_STRING);
			reqSb.append(header);
			reqSb.append("\n\n");
			rspSb.append(header);
			rspSb.append("\n\n");
		}

		while (this.hasNextTest()) {

			// TODO: the comments could be more efficient...
			String comment = p.getProperty("comment" + inputNo);
			String extraparam = p.getProperty("extraparam" + inputNo);
			if (comment != null) {
				// split comment along newlines to bracket each one
				String[] parts = comment.split("\n");
				for (String s : parts) {
					s = s.trim();
					reqSb.append("[");
					reqSb.append(s);
					reqSb.append("]\n");
					rspSb.append("[");
					rspSb.append(s);
					rspSb.append("]\n");
				}
				if (extraparam == null) {
					reqSb.append("\n");
					rspSb.append("\n");
				}
			}
			// TODO: this is very kludgy; extra params are things that aren't in brackets

			if (extraparam != null) {
				reqSb.append(extraparam);
				reqSb.append("\n\n");
				rspSb.append(extraparam);
				rspSb.append("\n\n");
			}
			List<byte[]> args = new ArrayList<byte[]>();
			// if we're a Monte Carlo test, we need to do something special here
			if (p.containsKey("output" + currentOutput + "_name") && 
				"montecarlo".equalsIgnoreCase(
					p.getProperty("output" + currentOutput + "_type"))) {
				// 100 repetitions by default
				int repetitions = Integer.valueOf(p.getProperty(
							"output" + currentOutput + "_repetitions", "100"));	
				// counter goes in argument 0 by default
				int countOutput = Integer.valueOf(p.getProperty(
						"output" + currentOutput + "_count", "0"));
				// we get the arguments similarly to a regular test, but
				// they get updated by the monte carlo routine and we 
				// print them every time
				List<String> argNames = new ArrayList<String>();
				List<Integer> showArg = new ArrayList<Integer>();
				int c = 0;
				for (Queue<Input> input : inputs) {
					argNames.add(input.peek().getName());
					showArg.add(input.peek().showInOutput());
					Entry<String, byte[]> e = input.peek().toReqString();
					prevValues.add(c++, e.getValue());
					args.add(e.getValue());
					// the request buffer gets the original arguments
					reqSb.append(e.getKey());
					reqSb.append("\n");
				}
				// for any inputs that are printed only once at the top of the output,
				// do that now
				for (int i = 0; i < args.size(); i++) {
					boolean added = false;
					if (showArg.get(i) == Input.ONCE) {
						rspSb.append(argNames.get(i) + " = " + Util.byteArrayToHexString(args.get(i)));
						rspSb.append("\n");
						added = true;
					}
					if (added) {
						rspSb.append("\n");
					}
				}
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
				String outputName = 
						p.getProperty("output" + currentOutput + "_name").trim();
				int countArg = Integer.parseInt(p.getProperty(
						"output" + currentOutput + "_count", "-1"));
				// if we end up with -1, we fabricate a count argument; if
				// we end up with any other negative number, we omit the count argument (unlikely)
				for (int count = 0; count < repetitions; count++) {
					// generate output for this iteration
					if (countArg == -1) {
						// we need to fabricate a count argument
						rspSb.append("COUNT = " + count + "\n");
					}
					for (int i = 0; i < args.size(); i++) {
						if (showArg.get(i) == Input.YES) {
							StringBuilder sb = new StringBuilder(argNames.get(i));

							sb.append(" = ");
							if (i == countArg) {
								sb.append(count);
							} else {
								sb.append(Util.byteArrayToHexString(args.get(i)));
							}
							sb.append("\n");
							// the response buffer gets one set of arguments per 
							// Monte Carlo execution
							rspSb.append(sb);
						}
					}
					rspSb.append(outputName);
					rspSb.append(" = ");
					// Output.monteCarlo _changes_ the contents of args for
					// the next run!
					byte[] result = Output.getMonteCarloOutput(func, args, argOrder);
					if (result.length == 0) {
						rspSb.append("? (no result due to algorithm issue)");
					} else {
						rspSb.append(Util.byteArrayToHexString(result));
					}
					rspSb.append("\n");
					if (count < repetitions - 1) {
						rspSb.append("\n");
					}
				}
			} else {
				int c = 0;
				for (Queue<Input> input : inputs) {
					Entry<String, byte[]> e = input.peek().toReqString();
					prevValues.add(c++, e.getValue());
					args.add(e.getValue());
					reqSb.append(e.getKey());
					reqSb.append("\n");
					if (input.peek().showInOutput() == Input.YES) {
						rspSb.append(e.getKey());
						rspSb.append("\n");
					}					
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
					byte[] result = Output.getOutput(func, args, argOrder);
					if (result.length == 0) {
						rspSb.append("? (no result due to algorithm issue)");
					} else {
						rspSb.append(Util.byteArrayToHexString(result));
					}
					rspSb.append("\n");
				}
			}
			reqSb.append("\n");
			rspSb.append("\n");
			inputNo++;
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

	public Req(String reqFileName, String defFileName) throws IOException {
		p = new Properties();
		FileInputStream in = new FileInputStream(defFileName);
		p.load(in);
		// clear the Galois header
		p.remove("header");
		in.close();
		
		Scanner scan = new Scanner(new File(reqFileName));

		Map<String, ListInput> inputs = initReqInputs();
		Set<String> extraparams = initExtraParams();

		while (scan.hasNextLine()) {
			String nextLine = scan.nextLine();
			if (!extraparams.contains(nextLine)) {
				parseReqLine(nextLine, inputs);
			}
		}
		scan.close();
	}

	private Map<String, ListInput> initReqInputs() {
		inputs = new ArrayList<Queue<Input>>();
		Map<String, ListInput> ret = new HashMap<String, ListInput>();
		int inputCt = Integer.parseInt(p.getProperty("inputs").trim());
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
				String showInOutputString =
						getStringProperty("showinoutput" + suff2, i, "yes");
				int showInOutput = Input.YES;
				switch (showInOutputString.toLowerCase()) {
					case "no": showInOutput = Input.NO; break;
					case "once": showInOutput = Input.ONCE; break;
					default:
				}
 
				ListInput li = new ListInput(inputName, isIntType(inputType), showInOutput);
				addInput(i, li);
				ret.put(inputName, li); // TODO: this only supports unique input
										// names
			}
		}
		return ret;
	}

	private Set<String> initExtraParams() {
		Set<String> result = new HashSet<String>();
		for (Object o : p.keySet()) {
			String s = (String) o; // all keys are known to be strings
			if (s.startsWith("extraparam")) {
				String ep = p.getProperty(s);
				String[] lines = ep.split("\n");
				result.addAll(Arrays.asList(lines));
			}
		}
		return result;
	}
	
	private void parseReqLine(String line, Map<String, ListInput> inputMap) {
		if (line.length() != 0 && line.charAt(0) == '#') {
			// we include the header comment verbatim, replacing the one from our
			// template file
			if (p.getProperty("header") == null) {
				p.setProperty("header", line);
			} else {
				// append to the header
				p.setProperty("header", p.getProperty("header") + "\n" + line);
			}
		} else if (line.length() != 0 && line.charAt(0) != '[' && line.contains(" = ")) {
			String[] kv = line.split(" = ");
			String name = kv[0];
			String value = kv[1];
	
			if (!inputMap.containsKey(name)) {
				throw new RuntimeException("Could not find input " + name
						+ " in input map");
			}
	
			ListInput li = inputMap.get(name);
			if (li.isInt()) {
				li.addInput(Integer.parseInt(value.trim()));
			} else {
				li.addInput(Util.hexStringToByteArray(value.trim()));
			}
		}
	}

	private boolean isIntType(String type) {
		switch (type.toUpperCase()) {
		case "LENGTH":
		case "COUNT":
		case "SEQUENCE":
			return true;
		default:
			return false;
		}
	}

	/**
	 * Create a Req object from a req file. The form of the req is given in the
	 * readme file for this project
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
				String showInOutputString =
						getStringProperty("showinoutput" + suff2, i, "yes");
				int showInOutput = Input.YES;
				switch (showInOutputString.toLowerCase()) {
					case "no": showInOutput = Input.NO; break;
					case "once": showInOutput = Input.ONCE; break;
					default:
				}
				switch (inputType.toUpperCase()) {

				case "LENGTH":
					int lengthOf = getIntProperty("lengthof" + suff2, i);
					String unit = getStringProperty("unit" + suff2, i);
					addInput(i,
							new LengthInput(inputName, lengthOf, this, unit, showInOutput));
					break;

				case "RANDOM": {
					int minLength = getIntProperty("minlength" + suff2, i);
					int maxLength = getIntProperty("maxlength" + suff2, i);
					int ct = getIntProperty("ct" + suff2, i);
					boolean parity = false;
					if (containsProperty("parity" + suff2, i)) {
						parity = true;
					}
					InputLength il = new RandomInputLength(minLength,
							maxLength, ct);
					addInput(i, new RandomInput(inputName, il, parity, showInOutput));
				}
					break;

				case "INCREASE": {
					int minLength = getIntProperty("minlength" + suff2, i);
					int maxLength = getIntProperty("maxlength" + suff2, i);
					int stepSize = getIntProperty("stepsize" + suff2, i);
					boolean parity = false;
					if (containsProperty("parity" + suff2, i)) {
						parity = true;
					}
					InputLength il = new StepInputLength(minLength, maxLength,
							stepSize);
					addInput(i, new RandomInput(inputName, il, parity, showInOutput));
				}
					break;

				case "RANDOMSEQUENCE": {
					int[] seq = Util.parseIntArray(getStringProperty("sequence"
							+ suff2, i));
					int repeat = getIntProperty("repeat" + suff2, i);
					int changeEvery = getIntProperty("changeEvery" + suff2, i);
					boolean parity = false;
					if (containsProperty("parity" + suff2, i)) {
						parity = true;
					}
					InputLength il = new SequenceLength(seq, repeat,
							changeEvery);
					addInput(i, new RandomInput(inputName, il, parity, showInOutput));
				}
					break;

				case "COUNT": {
					int min = getIntProperty("min" + suff2, i);
					int max = getIntProperty("max" + suff2, i);
					addInput(i, new CountInput(inputName, min, max, showInOutput));
				}
					break;

				case "RNGV": {
					addInput(i,
							new RngVInput(getIntProperty("length" + suff2, i), showInOutput));
					break;
				}

				case "FIXED": {
					int number = getIntProperty("number" + suff2, i);
					int increment = getIntProperty("increment", i);
					if (containsProperty("value" + suff2, i)) {
						String value = getStringProperty("value" + suff2, i);
						addInput(i,
								new FixedInput(
										Util.hexStringToByteArray(value),
										inputName, number, increment, showInOutput));
					} else {
						int length = getIntProperty("length" + suff2, i);
						addInput(i, new FixedInput(length, inputName, number,
								increment, showInOutput));
					}
					break;
				}

				case "SEQUENCE": {
					int[] seq = Util.parseIntArray(getStringProperty("values"
							+ suff2, i));
					int repeat = getIntProperty("repeat" + suff2, i);
					int changeEvery = getIntProperty("changeEvery" + suff2, i);
					addInput(i, new SequenceInput(inputName, seq, changeEvery,
							repeat, showInOutput));
					break;
				}

				case "COPY": {
					int copyOf = getIntProperty("copyof" + suff2, i);
					addInput(i, new CopyInput(inputName, copyOf, this, showInOutput));
				}
					break;

				default:
					throw new RuntimeException("Unknown test type: "
							+ inputType);
				}
			}
		}

	}

	public static void main(String args[]) {
		Req r;
		String fileName = "TDES/TCFB64varkey";
		File outDir = new File("output2");
		String testDir = "test_defs";
		fileName = fileName.replace('/', File.separatorChar);
		String dir = fileName.substring(0,
				fileName.lastIndexOf(File.separatorChar));
		try {
			r = new Req("output/req/TDES/TCFB64varkey.req", testDir + File.separator + fileName);
		} catch (IOException e) {
			throw new RuntimeException("could not read file: " + testDir
					+ File.separator + fileName);
		}

		Entry<String, String> reqrsp = r.createReqRsp();

		File rspdir = new File(outDir.getPath() + File.separator + "rsp"
				+ File.separator + dir);
		rspdir.mkdirs();
		Util.writeStringToOutDir(fileName + ".rsp", outDir.getPath()
				+ File.separator + "rsp", reqrsp.getValue());

	}
}
