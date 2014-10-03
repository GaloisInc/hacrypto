package com.galois.hacrypto.test;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;
import java.util.Scanner;

import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.engines.AESWrapPadEngine;
import org.bouncycastle.crypto.engines.DESedeWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Runs a set of key wrapping tests (for AES, AES with Padding, and DESede).
 * 
 * @author dmz
 */
public class RunKeyWrapTests {
	private static String PTL_START = "[PLAINTEXT LENGTH";
	private static String COUNT_START = "COUNT";
	private static byte[] DESEDE_IV = {
        (byte)0xa6, (byte)0xa6, (byte)0xa6, (byte)0xa6,
        (byte)0xa6, (byte)0xa6, (byte)0xa6, (byte)0xa6 };
	
	private class TestParams {
		public final int key_size;
		public final boolean wrap;
		public final boolean invert;
		
		public TestParams(final int the_key_size, 
				          final boolean the_wrap, final boolean the_invert) {
			key_size = the_key_size;
			wrap = the_wrap;
			invert = the_invert;
		}
	}
	
	private enum KeyWrapTestType {
		KW("KW_"),
		KWP("KWP_"),
		TKW("TKW_");

		private final String my_prefix; 
		
		private KeyWrapTestType(final String the_prefix) {
			my_prefix = the_prefix;
		}
		
		public String prefix() {
			return my_prefix;
		}
	}

	private class TestFileFilter implements FilenameFilter {
		private final String my_prefix;
		
		public TestFileFilter(final String the_prefix) {
			my_prefix = the_prefix;
		}
		
		public boolean accept(final File the_file, final String the_name) {
			return the_name.startsWith(my_prefix);
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
	public RunKeyWrapTests(final String the_test_dir, final String the_output_dir) {
		test_dir = new File(the_test_dir);
		if (!test_dir.isDirectory()) {
			throw new IllegalArgumentException(test_dir + " is not a directory");
		}
		
		output_dir = new File(the_output_dir);
		if (!output_dir.isDirectory() && !output_dir.mkdirs()) {
			throw new IllegalArgumentException(output_dir + " is not a directory");
		}
	}
	
	public void run() {
		for (KeyWrapTestType test : KeyWrapTestType.values()) {
			for (File tf : test_dir.listFiles(new TestFileFilter(test.prefix()))) {
				if (tf.isFile()) {
					runTest(test, tf);
				}
			}
		}
	}
	
	private void runTest(final KeyWrapTestType the_test, final File the_file) {
		try {
			switch (the_test) {
				//case KW: runKW(the_file, false); break;
				//case KWP: runKW(the_file, true); break;
				case TKW: runTKW(the_file); break;
				default: // this can't happen
			}
		} catch (final Exception e) {
			System.err.println("Failed to run tests for " + the_file.getPath());
			e.printStackTrace();
		}
	}
	
	/**
	 * Parses an AES test parameters object out of a filename.
	 * 
	 * @param the_file The file to parse the name of.
	 * @return The test parameters object.
	 */
	private TestParams parseParams(final File the_file) {
		final String filename = the_file.getName();

		final String trunc_filename = filename.substring(0, filename.indexOf('.'));
		final String[] parts = trunc_filename.split("_");
		
		int key_size = 192;
		boolean encrypt = false;
		boolean invert = false;
		
		if (parts.length < 2 || 4 < parts.length) {
			throw new IllegalArgumentException("Invalid file for a key wrap test: " + the_file);
		}
		
		encrypt = parts[1].charAt(1) == 'E';
		
		if (parts[0].startsWith("A")) {
			try {
				key_size = Integer.valueOf(parts[2]);
			} catch (NumberFormatException e) {
				throw new IllegalArgumentException("Invalid file for an AES test: " + the_file);
			}
		}
		
		if ("inv".equals(parts[parts.length - 1])) {
			invert = true;
		}
		
		return new TestParams(key_size, encrypt, invert);
	}
	
	/**
	 * Runs an AES key wrapping test on the specified file.
	 * 
	 * @param the_file The file on which to run tests.
	 * @param the_padding true to use padding, false otherwise
	 */
	private void runKW(final File the_file, boolean the_padding) throws IOException {
		final TestParams params = parseParams(the_file);
		final String filename = the_file.getName().substring(
				0, the_file.getName().indexOf('.'));

		if (params.invert) {
			System.err.println(filename + " tests not yet supported.");
			return;
		}

		System.err.println("Running " + filename + " tests");
		
		Scanner sc = new Scanner(the_file);
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last + "\n");
			last = sc.nextLine();
		}
		header.append("\n");
		
		final File out_file = new File(output_dir + File.separator + filename + ".rsp");
	    PrintWriter out = null;
		
		try {
			out_file.createNewFile();
			out = new PrintWriter(out_file);
		} catch (final Exception e) {
			System.err.println("Unable to create " + out_file);
			System.exit(1);
		}
		
		out.append(header);
		
		final String provided_string_char = params.wrap ? "P" : "C";

		// parse "PLAINTEXT LENGTH" lines and the things following them
		while (sc.hasNextLine()) {
			while (!last.toUpperCase().startsWith(PTL_START)) {
				last = sc.nextLine();
			}
			out.println(last);
			
			// for this test, we read and process COUNT/K/C until we hit 
			// another PLAINTEXT LENGTH
			
			last = sc.nextLine();
			while (sc.hasNextLine() && !last.toUpperCase().startsWith(PTL_START)) {
				while (!last.toUpperCase().startsWith(COUNT_START)) {
					out.println(last);
					last = sc.nextLine();
				}
								
				while (!last.toUpperCase().startsWith("K")) {
					out.println(last);
					last = sc.nextLine();
				}
				
				String[] line_parts = last.split(" = ");
				KeyParameter key = new KeyParameter(Util.hexStringToByteArray(line_parts[1]));
				
				while (!last.toUpperCase().startsWith(provided_string_char)) {
					out.println(last);
					last = sc.nextLine();
				}
				
				line_parts = last.split(" = ");
				byte[] provided = Util.hexStringToByteArray(line_parts[1]);
				
				out.println(last);
				last = sc.nextLine();
				
				// now we have a key and a provided string, let's wrap (or unwrap)!
				Wrapper aes;
				if (the_padding) {
					aes = new AESWrapPadEngine();
				} else {
					aes = new AESWrapEngine();
				}
				aes.init(params.wrap, key);
				if (params.wrap) {
					try {
						byte[] result = aes.wrap(provided, 0, provided.length);
						out.println("C = " + Util.byteArrayToHexString(result));
					} catch (Exception e) {
						out.println("C = ? (input length not supported)");
					}
				} else {
					try {
						byte[] result = aes.unwrap(provided, 0, provided.length);
						out.println("P = " + Util.byteArrayToHexString(result));
					} catch (Throwable ex) {
						out.println("FAIL");
					}
				}
			
				while (sc.hasNext() && !(last.trim().length() == 0) && 
					   !last.startsWith(COUNT_START) && 
					   !last.startsWith(PTL_START)) {
					out.println(last);
					last = sc.nextLine();
				}
				
				out.flush();
			}
		}
		sc.close();
		out.close();
	}

	/**
	 * Runs an DESede key wrapping test on the specified file.
	 * 
	 * @param the_file The file on which to run tests.
	 */
	private void runTKW(final File the_file) throws IOException {
		final TestParams params = parseParams(the_file);
		final String filename = the_file.getName().substring(
				0, the_file.getName().indexOf('.'));

		// if (params.invert) {
		if (true) { // the BouncyCastle Triple DES wrapper is not really usable
			System.err.println(filename + " tests not yet supported.");
			return;
		}

		System.err.println("Running " + filename + " tests");
		
		Scanner sc = new Scanner(the_file);
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last + "\n");
			last = sc.nextLine();
		}
		header.append("\n");
		
		final File out_file = new File(output_dir + File.separator + filename + ".rsp");
	    PrintWriter out = null;
		
		try {
			out_file.createNewFile();
			out = new PrintWriter(out_file);
		} catch (final Exception e) {
			System.err.println("Unable to create " + out_file);
			System.exit(1);
		}
		
		out.append(header);
		
		final String provided_string_char = params.wrap ? "P" : "C";

		// parse "PLAINTEXT LENGTH" lines and the things following them
		while (sc.hasNextLine()) {
			while (!last.toUpperCase().startsWith(PTL_START)) {
				last = sc.nextLine();
			}
			out.println(last);
			
			// for this test, we read and process COUNT/K/C until we hit 
			// another PLAINTEXT LENGTH
			
			last = sc.nextLine();
			while (sc.hasNextLine() && !last.toUpperCase().startsWith(PTL_START)) {
				while (!last.toUpperCase().startsWith(COUNT_START)) {
					out.println(last);
					last = sc.nextLine();
				}
								
				while (!last.toUpperCase().startsWith("K")) {
					out.println(last);
					last = sc.nextLine();
				}
				
				String[] line_parts = last.split(" = ");
				KeyParameter key = new KeyParameter(Util.hexStringToByteArray(line_parts[1]));
				
				while (!last.toUpperCase().startsWith(provided_string_char)) {
					out.println(last);
					last = sc.nextLine();
				}
				
				line_parts = last.split(" = ");
				byte[] provided = Util.hexStringToByteArray(line_parts[1]);
				
				out.println(last);
				last = sc.nextLine();
				
				// now we have a key and a provided string, let's wrap (or unwrap)!
				Wrapper desede = new DESedeWrapEngine();
				if (params.wrap) {
					ParametersWithIV iv_key = new ParametersWithIV(key, DESEDE_IV);
					desede.init(params.wrap, iv_key);
					try {
						byte[] result = desede.wrap(provided, 0, provided.length);
						out.println("C = " + Util.byteArrayToHexString(result));
					} catch (Exception e) {
						out.println("C = ? (input length not supported)");
					}
				} else {
					desede.init(params.wrap, key);
					try {
						byte[] result = desede.unwrap(provided, 0, provided.length);
						out.println("P = " + Util.byteArrayToHexString(result));
					} catch (Throwable ex) {
						System.err.println ("C = " + Util.byteArrayToHexString(provided));
						System.err.println("C length is " + provided.length);
						ex.printStackTrace();
						out.println("FAIL");
					}
				}
				
				while (sc.hasNext() && !(last.trim().length() == 0) && 
					   !last.startsWith(COUNT_START) && 
					   !last.startsWith(PTL_START)) {
					out.println(last);
					last = sc.nextLine();
				}
				
				out.flush();
			}
		}
		sc.close();
		out.close();
	}

	public static void main(final String... the_args) {
		if (the_args.length < 2) {
			System.err.println("directories for files must be specified");
			System.exit(1);
		}

		System.err.println("KeyWrap Tests for BouncyCastle Version " + (new BouncyCastleProvider()).getVersion());
		System.err.println("Starting run at " + new Date());
		long startTime = System.currentTimeMillis();

		RunKeyWrapTests stf = new RunKeyWrapTests(the_args[0], the_args[1]);
		stf.run();

		long finishTime = System.currentTimeMillis();
		System.err.println("Run ended at " + new Date());
		long msec = finishTime - startTime;
		long seconds = msec / 1000;
		msec = msec % 1000;
		long minutes = seconds / 60;
		seconds = seconds % 60;
		System.err.printf("Elapsed time: %d:%02d.%03d\n\n", minutes, seconds, msec);
	}
}
