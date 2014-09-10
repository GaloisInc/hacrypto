package com.galois.hacrypto.test;

import java.io.File;
import java.io.PrintWriter;
import java.util.Scanner;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Runs a set of DSA2 tests.
 * 
 * @author dmz
 */
public class RunDSATests {
	private static String ALG = "ZZ";
	private static String MOD_START = "[mod";
	
	private enum DSATestType {
		KEYPAIR("KeyPair.req"),
		PQG("PQGGen.req"),
		SIGGEN("SigGen.req"),
		SIGVER("SigVer.req");

		private final String my_filename; 
		
		private DSATestType(final String the_filename) {
			my_filename = the_filename;
		}
		
		public String filename() {
			return my_filename;
		}
	}
	
	/**
	 * The test directory.
	 */
	private final File test_dir;
	
	/**
	 * The output directory.
	 */
	private final File output_dir;
	
	/**
	 * Splits the tests in the specified directory. The names of the tests are
	 * required to be the standard names: KeyPair.req, PQGGen.req, SigGen.req, 
	 * and SigVer.req.
	 * 
	 * @param test_dir
	 */
	public RunDSATests(final String the_test_dir, final String the_output_dir) {
		test_dir = new File(the_test_dir);
		if (!test_dir.isDirectory()) {
			throw new IllegalArgumentException(test_dir + " is not a directory");
		}
		output_dir = new File(the_output_dir);
		if (!output_dir.isDirectory()) {
			throw new IllegalArgumentException(output_dir + " is not a directory");
		}
	}
	
	public void run() {
		for (DSATestType test : DSATestType.values()) {
			File tf = new File(test_dir.getPath() + File.separator + test.filename());
			if (tf.exists()) {
				System.err.println("Splitting " + tf.getPath());
				runTest(test, tf);
			}
		}
	}
	
	private void runTest(final DSATestType the_test, final File the_file) {
		try {
			Scanner sc = new Scanner(the_file);
			switch (the_test) {
				case KEYPAIR: runKeyPair(sc); break;
				case PQG: runPQG(sc); break;
				case SIGGEN: runSigGen(sc); break;
				case SIGVER: runSigVer(sc); break;
				default: // this can't happen
			}
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Parses a line beginning with "[mod =", breaking it out into a property list.
	 * 
	 * @param the_line The line.
	 * @return the property list.
	 */
	private SortedMap<String, String> parseMod(final String the_line) {
		final SortedMap<String, String> result = new TreeMap<String, String>();
		final String[] kv = the_line.split(" = ");
		
		if (kv.length != 2) {
			System.err.println("Malformed mod line: " + the_line);
			System.exit(1);
		}
		
		// drop the ending bracket
		kv[1] = kv[1].substring(0, kv[1].length() - 1);
		final String[] params = kv[1].split(", ");
		for (final String s : params) {
			final String[] pkv = s.split("=");
			if (pkv.length == 1) {
				// this is the algorithm, as it had no equals sign
				result.put(ALG, pkv[0]);
			} else {
				result.put(pkv[0], pkv[1]);
			}
		}
		
		System.err.println("Sanity check:");
		for (Object s : result.keySet()) {
			System.err.println(s + " = " + result.get(s));
		}
		
		return result;
	}
	
	/** 
	 * @param The parameters.
	 * @return a filename suffix based on the parameters.
	 */
	private String filenameSuffix(final SortedMap<String, String> the_params) {
		final StringBuilder sb = new StringBuilder();
		
		for (String key: the_params.keySet()) {
			sb.append(key);
			sb.append("=");
			sb.append(the_params.get(key));
			sb.append("_");
		}
		
		// remove the last "_"
		sb.deleteCharAt(sb.length() - 1);
		return sb.toString();
	}
	
	private void runKeyPair(final Scanner sc) {
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last + "\n");
			last = sc.nextLine();
		}
		header.append("\n");
		
		final File out_file = new File(output_dir + File.separator + "KeyPair.rsp");
	    PrintWriter out = null;
		
		try {
			out_file.createNewFile();
			out = new PrintWriter(out_file);
			System.err.println(out_file);
		} catch (final Exception e) {
			System.err.println("Unable to create " + out_file);
			System.exit(1);
		}
		
		out.append(header);
		
		// parse "mod" lines and the things following them
		while (sc.hasNextLine()) {
			while (!last.startsWith(MOD_START)) {
				last = sc.nextLine();
			}
			String mod = last;
			SortedMap<String, String> params = parseMod(mod);
			last = sc.nextLine();
			
			try {
				out.println(mod + "\n");
				while (sc.hasNextLine() && !last.startsWith(MOD_START)) {
					last = sc.nextLine();
					if (!last.startsWith(MOD_START)) {
						out.println(last);
					}
				}
			} catch (final Exception e) {
				throw new RuntimeException(e);
			}
		}
		
		out.close();
	}

	private void runPQG(final Scanner sc) {
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last);
			last = sc.nextLine();
		}
		
		// parse "mod" lines and the things following them
		while (sc.hasNextLine()) {
			while (!last.startsWith("[mod")) {
				last = sc.nextLine();
			}
			SortedMap<String, String> params = parseMod(last);
			last = sc.nextLine();
		}		
	}

	private void runSigGen(final Scanner sc) {
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last);
			last = sc.nextLine();
		}
		
		final File out_file = new File(output_dir + File.separator + "SigGen.rsp");
		try {
			out_file.createNewFile();
		} catch (final Exception e) {
			System.err.println("Unable to create " + out_file);
			System.exit(1);
		}
		
		// parse "mod" lines and the things following them
		while (sc.hasNextLine()) {
			while (!last.startsWith("[mod")) {
				last = sc.nextLine();
			}
			SortedMap<String, String> params = parseMod(last);
			last = sc.nextLine();
		}
	}

	private void runSigVer(final Scanner sc) {
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last);
			last = sc.nextLine();
		}
		
		// parse "mod" lines and the things following them
		while (sc.hasNextLine()) {
			while (!last.startsWith("[mod")) {
				last = sc.nextLine();
			}
			SortedMap<String, String> params = parseMod(last);
			last = sc.nextLine();
		}
		
	}
	
	public static void main(final String... the_args) {
		if (the_args.length < 2) {
			System.err.println("directories for files must be specified");
			System.exit(1);
		}
		
		RunDSATests stf = new RunDSATests(the_args[0], the_args[1]);
		stf.run();
	}
}
