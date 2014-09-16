package com.galois.hacrypto.test;

import java.io.File;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Scanner;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.DSAValidationParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

/**
 * Runs a set of DSA2 tests.
 * 
 * @author dmz
 */
public class RunDSATests {
	private static int HEX = 16;
	private static String MOD_START = "[MOD";
	
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
	 * A container class for DSA test parameters. They're public
	 * fields, which is pretty bad form, but since it's a private class
	 * and we're only using it here, it's probably OK.
	 */
	private class DSATestParams {
		public String alg;
		public int L;
		public int N;
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
		
		if (!output_dir.isDirectory() && !output_dir.mkdirs()) {
			throw new IllegalArgumentException(output_dir + " is not a directory");
		}
	}
	
	public void run() {
		for (DSATestType test : DSATestType.values()) {
			File tf = new File(test_dir.getPath() + File.separator + test.filename());
			if (tf.exists()) {
				System.err.println("Running tests for " + tf.getPath());
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
			sc.close();
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Parses a line beginning with "[mod =", breaking it out into 
	 * a test params object.
	 * 
	 * @param the_line The line.
	 * @return the params.
	 */
	private DSATestParams parseMod(final String the_line) {
		final DSATestParams result = new DSATestParams();
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
				result.alg = pkv[0];
			} else if (pkv[0].toUpperCase().equals("L")) {
				result.L = Integer.parseInt(pkv[1]);
			} else if (pkv[0].toUpperCase().equals("N")) {
				result.N = Integer.parseInt(pkv[1]);
			} else {
				throw new IllegalArgumentException("Unexpected input: " + the_line);
			}
		}
		
		return result;
	}
	
	/**
	 * @param the_int The big integer.
	 * @param the_digits The desired number of hex digits.
	 * @return a hex string of the specified length representing the big integer,
	 * with as many leading 0s as necessary.
	 */
	private String toHexString(final BigInteger the_int, final int the_digits) {
		final StringBuilder result = new StringBuilder();
		for (int i = 0; i < the_digits; i++) {
			result.append("0");
		}
		result.append(the_int.toString(HEX));
		return result.substring(result.length() - the_digits, result.length());
	}
	
	private void runKeyPair(final Scanner sc) {
		System.err.println("Running KeyPair tests");
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
		} catch (final Exception e) {
			System.err.println("Unable to create " + out_file);
			System.exit(1);
		}
		
		out.append(header);
		
		// parse "mod" lines and the things following them
		while (sc.hasNextLine()) {
			while (!last.toUpperCase().startsWith(MOD_START)) {
				last = sc.nextLine();
			}
			String mod = last;
			DSATestParams testparams = parseMod(mod);
			
			last = "";
			
			try {
				out.println(mod + "\n");
				
				// for this test, we read N from the req file and then,
				// N times, generate appropriate keys for the mod (L)
				// and SHA size (N). N is unfortunately overloaded here.
				
				while (!last.toUpperCase().startsWith("N")) {
					last = sc.nextLine();
				}
				
				String[] line_parts = last.split(" = ");
				int reps = Integer.parseInt(line_parts[1]);
				
				// first, we generate the domain parameters P, Q, G
						
				final DSAParametersGenerator dpg = new DSAParametersGenerator(new SHA256Digest());
				System.err.println("L=" + testparams.L + ", N=" + testparams.N);
				dpg.init(new DSAParameterGenerationParameters(
							testparams.L, testparams.N, 80, new SecureRandom()));
				final DSAParameters dsaparams = dpg.generateParameters();
				
				out.println("P = " + dsaparams.getP().toString(HEX));
				out.println("Q = " + dsaparams.getQ().toString(HEX));
				out.println("G = " + toHexString(dsaparams.getG(), 512));
				out.println("");
				
				// now, generate key pairs
				
				final DSAKeyPairGenerator kpg = new DSAKeyPairGenerator();
				kpg.init(new DSAKeyGenerationParameters(new SecureRandom(), dsaparams));

				for (int i = 0; i < reps; i++) {
					final AsymmetricCipherKeyPair pair = kpg.generateKeyPair();
					final DSAPrivateKeyParameters private_params = 
							(DSAPrivateKeyParameters) pair.getPrivate();
					final DSAPublicKeyParameters public_params = 
							(DSAPublicKeyParameters) pair.getPublic();
					out.println("X = " + private_params.getX().toString(HEX));
					out.println("Y = " + public_params.getY().toString(HEX));
					out.println("");
				}
				
			} catch (final Exception e) {
				out.close();
				throw new RuntimeException(e);
			}
			
			while (sc.hasNextLine() && !last.toUpperCase().startsWith(MOD_START)) {
				last = sc.nextLine();
			}
		}
		
		out.close();
	}

	private void runPQG(final Scanner sc) {
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last + "\n");
			last = sc.nextLine();
		}
		
		final File out_file = new File(output_dir + File.separator + "PQGGen.rsp");
	    PrintWriter out = null;
		
		try {
			out_file.createNewFile();
			out = new PrintWriter(out_file);
		} catch (final Exception e) {
			System.err.println("Unable to create " + out_file);
			System.exit(1);
		}
		
		out.append(header);

		// there are 3 parts to PQG: A.1.1.2, A.2.1, and A.2.3 (also others
		// that are not implemented here); let's branch to the right ones
		
		while (sc.hasNextLine()) {
			while (!last.toUpperCase().startsWith("[A.")) {
				out.println(last);
				last = sc.nextLine();
			}
			out.println(last);
			String[] words = last.toUpperCase().split(" ");
			switch (words[0]) {
				case "[A.1.1.2": last = pqgA112(sc, out); break;
				case "[A.2.1": last = pqgA21(sc, out); break;
				case "[A.2.3": last = pqgA23(sc, out); break;
				default: 
					throw new RuntimeException("unexpected FIPS 186-4 section: " + words[0]);
			}
			while (sc.hasNextLine() && last.trim().length() == 0) {
				last = sc.nextLine();
			}
		}
	}

	private String pqgA112(final Scanner the_scanner, final PrintWriter the_output) {
		System.err.println("PQG Section A.1.1.2");
		
		String last = "";
		the_output.println();
		
		// parse "mod" lines and the things following them
		while (!last.toUpperCase().startsWith("[A.") && the_scanner.hasNextLine()) {
			while (!last.toUpperCase().startsWith(MOD_START)) {
				last = the_scanner.nextLine();
			}
			String mod = last;
			DSATestParams testparams = parseMod(mod);
			
			last = the_scanner.nextLine();
			try {
				the_output.println(mod + "\n");
				
				// we need to read the "Num" line to tell us how many repetitions to do
				
				while (!last.toUpperCase().startsWith("NUM")) {
					last = the_scanner.nextLine();
				}
				
				String[] line_parts = last.split(" = ");
				int reps = Integer.valueOf(line_parts[1]);

				System.err.println("L=" + testparams.L + ", N=" + testparams.N 
						+ ", alg=" + testparams.alg);

				for (int i = 0; i < reps; i++) {
					// for each repetition, we need to generate a P and a Q, then output
					// them, the domain parameter seed, and the counter from generating P
					
					// generate the Digest object first
					Digest d = null;
					
					try {
						switch (testparams.alg) {
							case "SHA-1": d = new SHA1Digest(); break; 
							case "SHA-224": d = new SHA224Digest(); break;
							case "SHA-256": d = new SHA256Digest(); break;
							case "SHA-384": d = new SHA384Digest(); break;
							case "SHA-512": d = new SHA512Digest(); break;
							case "SHA-512/224": d = new SHA512tDigest(224); break;
							case "SHA-512/256": d = new SHA512tDigest(256); break;
							default:
								throw new RuntimeException("Unexpected algorithm: " + testparams.alg);
						}
					} catch (final Throwable cnfe) {
						System.err.println("Class not found for algorithm " + testparams.alg + ", skipping tests");
						the_output.println("P = ? (algorithm " + testparams.alg + " not available)");
						the_output.println("Q = ? (algorithm " + testparams.alg + " not available)");
						the_output.println("domain_parameter_seed = ? (algorithm " + testparams.alg + " not available)");
						the_output.println("counter = ? (algorithm " + testparams.alg + " not available)\n");
						the_output.flush();
						continue;
					}
					
					final DSAParametersGenerator dpg = new DSAParametersGenerator(d);
					dpg.init(new DSAParameterGenerationParameters(
								testparams.L, testparams.N, 80, new SecureRandom()));
					final DSAParameters dsaparams = dpg.generateParameters();
					final DSAValidationParameters valparams = dsaparams.getValidationParameters();
					
					the_output.println("P = " + dsaparams.getP().toString(HEX));
					the_output.println("Q = " + dsaparams.getQ().toString(HEX));
					the_output.println("domain_parameter_seed = " 
							+ Util.byteArrayToHexString(valparams.getSeed()));
					the_output.println("counter = " + valparams.getCounter());
					the_output.println();
					the_output.flush();
				}
			} catch (final Exception e) {
				the_output.close();
				throw new RuntimeException(e);
			} 
			while (the_scanner.hasNextLine() && !last.toUpperCase().startsWith(MOD_START)
					&& !last.toUpperCase().startsWith("[A.")) {
				last = the_scanner.nextLine();
			}
		}
		
		return last;
	}
	
	private String pqgA21(final Scanner the_scanner, final PrintWriter the_output) {
		System.err.println("PQG Section A.2.1");
		
		String last = "";
		the_output.println("");
		
		// parse "mod" lines and the things following them
		while (!last.toUpperCase().startsWith("[A.") && the_scanner.hasNextLine()) {
			while (!last.toUpperCase().startsWith(MOD_START)) {
				last = the_scanner.nextLine();
			}
			String mod = last;
			DSATestParams testparams = parseMod(mod);
			
			last = the_scanner.nextLine();
			try {
				the_output.println(mod + "\n");
				
				// we need to read the "Num" line to tell us how many repetitions to do
				
				while (!last.toUpperCase().startsWith("NUM")) {
					last = the_scanner.nextLine();
				}
				
				String[] line_parts = last.split(" = ");
				int reps = Integer.valueOf(line_parts[1]);

				System.err.println("L=" + testparams.L + ", N=" + testparams.N 
						+ ", alg=" + testparams.alg);

				for (int i = 0; i < reps; i++) {
					// for each repetition, we need to read a P and a Q, then output
					// the resulting G
	
					while (!last.toUpperCase().startsWith("P =")) {
						last = the_scanner.nextLine();
					}

					the_output.println(last);

					line_parts = last.split(" = ");
					BigInteger p = new BigInteger(line_parts[1], HEX);
					
					while (!last.toUpperCase().startsWith("Q =")) {
						last = the_scanner.nextLine();
						the_output.println(last);
					}
					
					line_parts = last.split(" = ");
					BigInteger q = new BigInteger(line_parts[1], HEX);
										
					// do DSA parameter generation with this P and Q
					
					BigInteger g = DSAParametersGenerator.calculateGenerator_FIPS186_3_Unverifiable(
							p, q, new SecureRandom());
					
					the_output.println("G = " + toHexString(g, testparams.L / 4));
					the_output.println();
					the_output.flush();
				}
			} catch (final Exception e) {
				the_output.close();
				throw new RuntimeException(e);
			} 
			while (the_scanner.hasNextLine() && !last.toUpperCase().startsWith(MOD_START)
					&& !last.toUpperCase().startsWith("[A.")) {
				last = the_scanner.nextLine();
			}
		}
		
		return last;
	}
	
	private String pqgA23(final Scanner the_scanner, final PrintWriter the_output) {
		System.err.println("PQG Section A.2.3");
		the_output.println();
		
		String last = "";
		// parse "mod" lines and the things following them
		while (!last.toUpperCase().startsWith("[A.") && the_scanner.hasNextLine()) {
			while (!last.toUpperCase().startsWith(MOD_START)) {
				last = the_scanner.nextLine();
			}
			String mod = last;
			DSATestParams testparams = parseMod(mod);
			
			last = the_scanner.nextLine();
			try {
				the_output.println(mod + "\n");
				
				// we need to read the "Num" line to tell us how many repetitions to do
				
				while (!last.toUpperCase().startsWith("NUM")) {
					last = the_scanner.nextLine();
				}
				
				String[] line_parts = last.split(" = ");
				int reps = Integer.valueOf(line_parts[1]);

				System.err.println("L=" + testparams.L + ", N=" + testparams.N 
						+ ", alg=" + testparams.alg);

				for (int i = 0; i < reps; i++) {
					// for each repetition, we need to read a P, a Q, a
					// domain_parameter_seed, and an index
	
					// we check for a remaining line here as a workaround for bad vectors
					while (the_scanner.hasNextLine() && !last.toUpperCase().startsWith("P =")) {
						last = the_scanner.nextLine();
					}
					if (!the_scanner.hasNextLine()) {
						continue;
					}
					the_output.println(last);
					line_parts = last.split(" = ");
					BigInteger p = new BigInteger(line_parts[1], HEX);
					
					while (!last.toUpperCase().startsWith("Q =")) {
						last = the_scanner.nextLine();
						the_output.println(last);
					}
					
					line_parts = last.split(" = ");
					BigInteger q = new BigInteger(line_parts[1], HEX);

					while (!last.toUpperCase().startsWith("DOMAIN_PARAMETER_SEED =")) {
						last = the_scanner.nextLine();
						the_output.println(last);
					}
					
					line_parts = last.split(" = ");
					byte[] dpseed = Util.hexStringToByteArray(line_parts[1]);
					
					while (!last.toUpperCase().startsWith("INDEX =")) {
						last = the_scanner.nextLine();
						the_output.println(last);
					}
					
					line_parts = last.split(" = ");
					int index = Integer.parseInt(line_parts[1], 16);
										
					// do DSA parameter generation with this P and Q
					// generate the Digest object first
					Digest d = null;
					
					try {
						switch (testparams.alg) {
							case "SHA-1": d = new SHA1Digest(); break; 
							case "SHA-224": d = new SHA224Digest(); break;
							case "SHA-256": d = new SHA256Digest(); break;
							case "SHA-384": d = new SHA384Digest(); break;
							case "SHA-512": d = new SHA512Digest(); break;
							case "SHA-512/224": d = new SHA512tDigest(224); break;
							case "SHA-512/256": d = new SHA512tDigest(256); break;
							default:
								throw new RuntimeException("Unexpected algorithm: " + testparams.alg);
						}
					} catch (final Throwable cnfe) {
						System.err.println("Class not found for algorithm " + testparams.alg + ", skipping tests");
						the_output.println("G = ? (test skipped, " + testparams.alg + " not available)\n");
						the_output.flush();
						continue;
					}
					
					BigInteger g = DSAParametersGenerator.calculateGenerator_FIPS186_3_Verifiable(
							d, p, q, dpseed, index);
					
					the_output.println("G = " + toHexString(g, testparams.L / 4));
					the_output.println();
					the_output.flush();
				}
			} catch (final Exception e) {
				the_output.close();
				throw new RuntimeException(e);
			} 
			while (the_scanner.hasNextLine() && !last.toUpperCase().startsWith(MOD_START)
					&& !last.toUpperCase().startsWith("[A.")) {
				last = the_scanner.nextLine();
			}
		}	
		
		return last;
	}
	
	private void runSigGen(final Scanner sc) {
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last + "\n");
			last = sc.nextLine();
		}
		
		final File out_file = new File(output_dir + File.separator + "SigGen.rsp");
	    PrintWriter out = null;
		
		try {
			out_file.createNewFile();
			out = new PrintWriter(out_file);
		} catch (final Exception e) {
			System.err.println("Unable to create " + out_file);
			System.exit(1);
		}
		
		out.append(header);
		
		// parse "mod" lines and the things following them
		while (sc.hasNextLine()) {
			while (!last.toUpperCase().startsWith(MOD_START)) {
				last = sc.nextLine();
			}
			String mod = last;
			DSATestParams testparams = parseMod(mod);
			
			last = "";
			
			try {
				out.println(mod + "\n");

				// first, we generate the domain parameters P, Q, G
														
				final DSAParametersGenerator dpg = new DSAParametersGenerator(new SHA256Digest());
				System.err.println("L=" + testparams.L 
						+ ", N=" + testparams.N + ", alg=" + testparams.alg);
				dpg.init(new DSAParameterGenerationParameters(
							testparams.L, testparams.N, 80, new SecureRandom()));
				final DSAParameters dsaparams = dpg.generateParameters();
				
				out.println("P = " + dsaparams.getP().toString(HEX));
				out.println("Q = " + dsaparams.getQ().toString(HEX));
				out.println("G = " + dsaparams.getG().toString(HEX));
				out.println("");
				
				
				// for this test, we repeatedly read a Msg from the
				// test file and then sign those messages, outputting
				// the domain parameters used (above, once for each
				// set of algorithm parameters) and the public key to
				// validate the signature as well as the computed signature 
				// values
				
				while (sc.hasNextLine() && !last.startsWith(MOD_START)) {
					while (!last.toUpperCase().startsWith("MSG")) {
						last = sc.nextLine();
					}

					String[] line_parts = last.split(" = ");
					Digest msg_d = null;
					byte[] digested_msg = null;

					try {
						switch (testparams.alg) {
							case "SHA-224": msg_d = new SHA224Digest(); break;
							case "SHA-256": msg_d = new SHA256Digest(); break;
							case "SHA-384": msg_d = new SHA384Digest(); break;
							case "SHA-512": msg_d = new SHA512Digest(); break;
							default:
								throw new RuntimeException("Unexpected algorithm: " + testparams.alg);
						}
					} catch (final Throwable cnfe) {
						System.err.println("Class not found for algorithm " + testparams.alg + ", skipping tests");
						out.println("\n\n\n\n\n");
						out.flush();
						last = "";
						while (sc.hasNextLine() && last.trim().length() == 0) {
							last = sc.nextLine();
						}
						continue;
					}
					
					byte[] msg = Util.hexStringToByteArray(line_parts[1]);
					digested_msg = new byte[msg_d.getDigestSize()];
					msg_d.update(msg, 0, msg.length);
					msg_d.doFinal(digested_msg, 0);
					
					// now, generate key pairs and sign messages

					final DSAKeyPairGenerator kpg = new DSAKeyPairGenerator();
					kpg.init(new DSAKeyGenerationParameters(new SecureRandom(), dsaparams));

					final AsymmetricCipherKeyPair pair = kpg.generateKeyPair();
					final DSAPrivateKeyParameters private_params = 
							(DSAPrivateKeyParameters) pair.getPrivate();
					final DSAPublicKeyParameters public_params = 
							(DSAPublicKeyParameters) pair.getPublic();
					
					out.println(last);
					out.println("Y = " + toHexString(public_params.getY(), testparams.L / 8));
					
					final DSASigner signer = new DSASigner();
					signer.init(true, private_params);
					final BigInteger[] signature = signer.generateSignature(digested_msg);
					out.println("R = " + toHexString(signature[0], 20));
					out.println("S = " + toHexString(signature[1], 20));
					out.println("");
					last = "";
					while (sc.hasNextLine() && last.trim().length() == 0) {
						last = sc.nextLine();
					}
				}
			} catch (final Exception e) {
				out.close();
				throw new RuntimeException(e);
			}
			
			while (sc.hasNextLine() && !last.toUpperCase().startsWith(MOD_START)) {
				last = sc.nextLine();
			}
		}
		
		out.close();
	}

	private void runSigVer(final Scanner sc) {
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last + "\n");
			last = sc.nextLine();
		}
		
		final File out_file = new File(output_dir + File.separator + "SigVer.rsp");
	    PrintWriter out = null;
		
		try {
			out_file.createNewFile();
			out = new PrintWriter(out_file);
		} catch (final Exception e) {
			System.err.println("Unable to create " + out_file);
			System.exit(1);
		}
		
		out.append(header + "\n");
		
		// parse "mod" lines and the things following them
		while (sc.hasNextLine()) {
			while (!last.toUpperCase().startsWith(MOD_START)) {
				last = sc.nextLine();
			}
			String mod = last;
			DSATestParams testparams = parseMod(mod);
			
			last = sc.nextLine();
			
			try {
				out.println(mod);

				// first, we read the domain parameters P, Q, G
								
				while (!last.toUpperCase().startsWith("P =")) {
					out.println(last);
					last = sc.nextLine();
				}
				
				String[] line_parts = last.split(" = ");
				BigInteger p = new BigInteger(line_parts[1], HEX);
				
				while (!last.toUpperCase().startsWith("Q =")) {
					out.println(last);
					last = sc.nextLine();
				}
				
				line_parts = last.split(" = ");
				BigInteger q = new BigInteger(line_parts[1], HEX);
				
				while (!last.toUpperCase().startsWith("G = ")) {
					out.println(last);
					last = sc.nextLine();
				}
				
				line_parts = last.split(" = ");
				BigInteger g = new BigInteger(line_parts[1], HEX);
				out.println(last + "\n");
				
				// make a DSAParameters from these parameters
				
				System.err.println("L=" + testparams.L 
						+ ", N=" + testparams.N + ", alg=" + testparams.alg);
				final DSAParameters dsaparams = new DSAParameters(p, q, g);
				
				// for this test, we repeatedly read a Msg, Y, R and S
				// from the input file and try to validate the signature,
				// reporting success or failure
				
				while (sc.hasNextLine() && !last.toUpperCase().startsWith(MOD_START)) {
					// read Msg
					out.flush();
					while (!last.toUpperCase().startsWith("MSG")) {
						last = sc.nextLine();
					}

					line_parts = last.split(" = ");
					Digest msg_d = null;
					byte[] digested_msg = null;

					try {
						switch (testparams.alg) {
							case "SHA-1": msg_d = new SHA1Digest(); break; 
							case "SHA-224": msg_d = new SHA224Digest(); break;
							case "SHA-256": msg_d = new SHA256Digest(); break;
							case "SHA-384": msg_d = new SHA384Digest(); break;
							case "SHA-512": msg_d = new SHA512Digest(); break;
							default:
								throw new RuntimeException("Unexpected algorithm: " + testparams.alg);
						}
					} catch (final Throwable cnfe) {
						System.err.println("Class not found for algorithm " + testparams.alg + ", skipping tests");
						out.println("\n\n\n\n\n");
						out.flush();
						while (!last.toUpperCase().startsWith("S")) {
							last = sc.nextLine();
						}
						last = "";
						while (sc.hasNextLine() && last.trim().length() == 0) {
							last = sc.nextLine();
						}
						continue;
					}
					
					byte[] msg = Util.hexStringToByteArray(line_parts[1]);
					digested_msg = new byte[msg_d.getDigestSize()];
					msg_d.update(msg, 0, msg.length);
					msg_d.doFinal(digested_msg, 0);
					
					// read Y
					while (!last.toUpperCase().startsWith("Y")) {
						out.println(last);
						last = sc.nextLine();
					}
					
					line_parts = last.split(" = ");
					final BigInteger y = new BigInteger(line_parts[1], HEX);
					
					// read R
					while (!last.toUpperCase().startsWith("R")) {
						out.println(last);
						last = sc.nextLine();
					}
					
					line_parts = last.split(" = ");
					final BigInteger r = new BigInteger(line_parts[1], HEX);

					// read S
					while (!last.toUpperCase().startsWith("S")) {
						out.println(last);
						last = sc.nextLine();
					}
					
					line_parts = last.split(" = ");
					final BigInteger s = new BigInteger(line_parts[1], HEX);

					// now, check the signature

					final DSASigner signer = new DSASigner();
					signer.init(false, new DSAPublicKeyParameters(y, dsaparams));
					
					final boolean ok = signer.verifySignature(digested_msg, r, s);
					
					out.println(last);
					String ok_string = "F";
					if (ok) { 
						ok_string = "P";
					}
					out.println("Result = " + ok_string);
					out.println("");
					last = "";
					while (sc.hasNextLine() && last.trim().length() == 0) {
						last = sc.nextLine();
					}
				}
			} catch (final Exception e) {
				out.close();
				throw new RuntimeException(e);
			}
			
			while (sc.hasNextLine() && !last.toUpperCase().startsWith(MOD_START)) {
				last = sc.nextLine();
			}
		}
		
		out.close();
	}
	
	public static void main(final String... the_args) {
		if (the_args.length < 2) {
			System.err.println("directories for files must be specified");
			System.exit(1);
		}

		System.err.println("DSA Tests for BouncyCastle Version " + (new BouncyCastleProvider()).getVersion());
		System.err.println("Starting run at " + new Date());
		long startTime = System.currentTimeMillis();

		RunDSATests stf = new RunDSATests(the_args[0], the_args[1]);
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
	
	// Pasted directly from the BouncyCastle source code for DSA parameter
	// generation, with additional facades as indicated to expose private methods.
	/**
	 * Generate suitable parameters for DSA, in line with FIPS 186-2, or FIPS 186-3.
	 */
	private static class DSAParametersGenerator
	{
	    private Digest          digest;
	    private int             L, N;
	    private int             certainty;
	    private SecureRandom    random;

	    private static final BigInteger ZERO = BigInteger.valueOf(0);
	    private static final BigInteger ONE = BigInteger.valueOf(1);
	    private static final BigInteger TWO = BigInteger.valueOf(2);

	    private boolean use186_3;
	    private int usageIndex;

	    /* constructor commented out because it is never used in DSA2 tests
	    public DSAParametersGenerator()
	    {
	        // BEGIN android-changed
	        this(AndroidDigestFactory.getSHA1());
	        // END android-changed
	    }
		*/
	    
	    public DSAParametersGenerator(Digest digest)
	    {
	        this.digest = digest;
	    }

	    /**
	     * initialise the key generator.
	     *
	     * @param size size of the key (range 2^512 -> 2^1024 - 64 bit increments)
	     * @param certainty measure of robustness of prime (for FIPS 186-2 compliance this should be at least 80).
	     * @param random random byte source.
	     */
	    public void init(
	        int             size,
	        int             certainty,
	        SecureRandom    random)
	    {
	        this.use186_3 = false;
	        this.L = size;
	        this.N = getDefaultN(size);
	        this.certainty = certainty;
	        this.random = random;
	    }

	    /**
	     * Initialise the key generator for DSA 2.
	     * <p>
	     *     Use this init method if you need to generate parameters for DSA 2 keys.
	     * </p>
	     *
	     * @param params  DSA 2 key generation parameters.
	     */
	    public void init(
	        DSAParameterGenerationParameters params)
	    {
	        // TODO Should we enforce the minimum 'certainty' values as per C.3 Table C.1?
	        this.use186_3 = true;
	        this.L = params.getL();
	        this.N = params.getN();
	        this.certainty = params.getCertainty();
	        this.random = params.getRandom();
	        this.usageIndex = params.getUsageIndex();

	        if ((L < 1024 || L > 3072) || L % 1024 != 0)
	        {
	            throw new IllegalArgumentException("L values must be between 1024 and 3072 and a multiple of 1024");
	        }
	        else if (L == 1024 && N != 160)
	        {
	            throw new IllegalArgumentException("N must be 160 for L = 1024");
	        }
	        else if (L == 2048 && (N != 224 && N != 256))
	        {
	            throw new IllegalArgumentException("N must be 224 or 256 for L = 2048");
	        }
	        else if (L == 3072 && N != 256)
	        {
	            throw new IllegalArgumentException("N must be 256 for L = 3072");
	        }

	        if (digest.getDigestSize() * 8 < N)
	        {
	            throw new IllegalStateException("Digest output size too small for value of N");
	        }
	    }

	    /**
	     * which generates the p and g values from the given parameters,
	     * returning the DSAParameters object.
	     * <p>
	     * Note: can take a while...
	     */
	    public DSAParameters generateParameters()
	    {
	        return (use186_3)
	            ? generateParameters_FIPS186_3()
	            : generateParameters_FIPS186_2();
	    }

	    private DSAParameters generateParameters_FIPS186_2()
	    {
	        byte[]          seed = new byte[20];
	        byte[]          part1 = new byte[20];
	        byte[]          part2 = new byte[20];
	        byte[]          u = new byte[20];
	        int             n = (L - 1) / 160;
	        byte[]          w = new byte[L / 8];

	        // BEGIN android-changed
	        if (!(digest.getAlgorithmName().equals("SHA-1")))
	        // END android-changed
	        {
	            throw new IllegalStateException("can only use SHA-1 for generating FIPS 186-2 parameters");
	        }

	        for (;;)
	        {
	            random.nextBytes(seed);

	            hash(digest, seed, part1);
	            System.arraycopy(seed, 0, part2, 0, seed.length);
	            inc(part2);
	            hash(digest, part2, part2);

	            for (int i = 0; i != u.length; i++)
	            {
	                u[i] = (byte)(part1[i] ^ part2[i]);
	            }

	            u[0] |= (byte)0x80;
	            u[19] |= (byte)0x01;

	            BigInteger q = new BigInteger(1, u);

	            if (!q.isProbablePrime(certainty))
	            {
	                continue;
	            }

	            byte[] offset = Arrays.clone(seed);
	            inc(offset);

	            for (int counter = 0; counter < 4096; ++counter)
	            {
	                for (int k = 0; k < n; k++)
	                {
	                    inc(offset);
	                    hash(digest, offset, part1);
	                    System.arraycopy(part1, 0, w, w.length - (k + 1) * part1.length, part1.length);
	                }

	                inc(offset);
	                hash(digest, offset, part1);
	                System.arraycopy(part1, part1.length - ((w.length - (n) * part1.length)), w, 0, w.length - n * part1.length);

	                w[0] |= (byte)0x80;

	                BigInteger x = new BigInteger(1, w);

	                BigInteger c = x.mod(q.shiftLeft(1));

	                BigInteger p = x.subtract(c.subtract(ONE));

	                if (p.bitLength() != L)
	                {
	                    continue;
	                }

	                if (p.isProbablePrime(certainty))
	                {
	                    BigInteger g = calculateGenerator_FIPS186_2(p, q, random);

	                    return new DSAParameters(p, q, g, new DSAValidationParameters(seed, counter));
	                }
	            }
	        }
	    }

	    private static BigInteger calculateGenerator_FIPS186_2(BigInteger p, BigInteger q, SecureRandom r)
	    {
	        BigInteger e = p.subtract(ONE).divide(q);
	        BigInteger pSub2 = p.subtract(TWO);

	        for (;;)
	        {
	            BigInteger h = BigIntegers.createRandomInRange(TWO, pSub2, r);
	            BigInteger g = h.modPow(e, p);
	            if (g.bitLength() > 1)
	            {
	                return g;
	            }
	        }
	    }

	    /**
	     * generate suitable parameters for DSA, in line with
	     * <i>FIPS 186-3 A.1 Generation of the FFC Primes p and q</i>.
	     */
	    private DSAParameters generateParameters_FIPS186_3()
	    {
	    	// A.1.1.2 Generation of the Probable Primes p and q Using an Approved Hash Function
	        // FIXME This should be configurable (digest size in bits must be >= N)
	        Digest d = digest;
	        int outlen = d.getDigestSize() * 8;

	        // 1. Check that the (L, N) pair is in the list of acceptable (L, N pairs) (see Section 4.2). If
	        //	    the pair is not in the list, then return INVALID.
	        // Note: checked at initialisation

	        // 2. If (seedlen < N), then return INVALID.
	        // FIXME This should be configurable (must be >= N)
	        int seedlen = N;
	        byte[] seed = new byte[seedlen / 8];

	        // 3. n = ceiling(L ⁄ outlen) – 1.
	        int n = (L - 1) / outlen;

	        // 4. b = L – 1 – (n ∗ outlen).
	        int b = (L - 1) % outlen;

	        byte[] output = new byte[d.getDigestSize()];
	        for (;;)
	        {
	        	// 5. Get an arbitrary sequence of seedlen bits as the domain_parameter_seed.
	            random.nextBytes(seed);

	            // 6. U = Hash (domain_parameter_seed) mod 2^(N–1).
	            hash(d, seed, output);

	            BigInteger U = new BigInteger(1, output).mod(ONE.shiftLeft(N - 1));

	            // 7. q = 2^(N–1) + U + 1 – ( U mod 2).
	            BigInteger q = ONE.shiftLeft(N - 1).add(U).add(ONE).subtract(U.mod(TWO));

	            // 8. Test whether or not q is prime as specified in Appendix C.3.
	            // TODO Review C.3 for primality checking
	            if (!q.isProbablePrime(certainty))
	            {
	            	// 9. If q is not a prime, then go to step 5.
	                continue;
	            }

	            // 10. offset = 1.
	            // Note: 'offset' value managed incrementally
	            byte[] offset = Arrays.clone(seed);

	            // 11. For counter = 0 to (4L – 1) do
	            int counterLimit = 4 * L;
	            for (int counter = 0; counter < counterLimit; ++counter)
	            {
	            	// 11.1 For j = 0 to n do
	            	//	      Vj = Hash ((domain_parameter_seed + offset + j) mod 2^seedlen).
	            	// 11.2 W = V0 + (V1 ∗ 2^outlen) + ... + (V^(n–1) ∗ 2^((n–1) ∗ outlen)) + ((Vn mod 2^b) ∗ 2^(n ∗ outlen)).
	                // TODO Assemble w as a byte array
	                BigInteger W = ZERO;
	                for (int j = 0, exp = 0; j <= n; ++j, exp += outlen)
	                {
	                    inc(offset);
	                    hash(d, offset, output);

	                    BigInteger Vj = new BigInteger(1, output);
	                    if (j == n)
	                    {
	                        Vj = Vj.mod(ONE.shiftLeft(b));
	                    }

	                    W = W.add(Vj.shiftLeft(exp));
	                }

	                // 11.3 X = W + 2^(L–1). Comment: 0 ≤ W < 2L–1; hence, 2L–1 ≤ X < 2L.
	                BigInteger X = W.add(ONE.shiftLeft(L - 1));
	 
	                // 11.4 c = X mod 2q.
	                BigInteger c = X.mod(q.shiftLeft(1));

	                // 11.5 p = X - (c - 1). Comment: p ≡ 1 (mod 2q).
	                BigInteger p = X.subtract(c.subtract(ONE));

	                // 11.6 If (p < 2^(L - 1)), then go to step 11.9
	                if (p.bitLength() != L)
	                {
	                    continue;
	                }

	                // 11.7 Test whether or not p is prime as specified in Appendix C.3.
	                // TODO Review C.3 for primality checking
	                if (p.isProbablePrime(certainty))
	                {
	                	// 11.8 If p is determined to be prime, then return VALID and the values of p, q and
	                	//	      (optionally) the values of domain_parameter_seed and counter.
	                    if (usageIndex >= 0)
	                    {
	                        BigInteger g = calculateGenerator_FIPS186_3_Verifiable(d, p, q, seed, usageIndex);
	                        if (g != null)
	                        {
	                           return new DSAParameters(p, q, g, new DSAValidationParameters(seed, counter, usageIndex));
	                        }
	                    }

	                    BigInteger g = calculateGenerator_FIPS186_3_Unverifiable(p, q, random);

	                    return new DSAParameters(p, q, g, new DSAValidationParameters(seed, counter));
	                }

	                // 11.9 offset = offset + n + 1.      Comment: Increment offset; then, as part of
	                //	                                    the loop in step 11, increment counter; if
	                //	                                    counter < 4L, repeat steps 11.1 through 11.8.
	                // Note: 'offset' value already incremented in inner loop
	            }
	            // 12. Go to step 5.
	        }
	    }

	    public static BigInteger calculateGenerator_FIPS186_3_Unverifiable(BigInteger p, BigInteger q,
	        SecureRandom r)
	    {
	        return calculateGenerator_FIPS186_2(p, q, r);
	    }

	    public static BigInteger calculateGenerator_FIPS186_3_Verifiable(Digest d, BigInteger p, BigInteger q,
	        byte[] seed, int index)
	    {
	    	// A.2.3 Verifiable Canonical Generation of the Generator g
	        BigInteger e = p.subtract(ONE).divide(q);
	        byte[] ggen = Hex.decode("6767656E");

	        // 7. U = domain_parameter_seed || "ggen" || index || count.
	        byte[] U = new byte[seed.length + ggen.length + 1 + 2];
	        System.arraycopy(seed, 0, U, 0, seed.length);
	        System.arraycopy(ggen, 0, U, seed.length, ggen.length);
	        U[U.length - 3] = (byte)index;

	        byte[] w = new byte[d.getDigestSize()];
	        for (int count = 1; count < (1 << 16); ++count)
	        {
	            inc(U);
	            hash(d, U, w);
	            BigInteger W = new BigInteger(1, w);
	            BigInteger g = W.modPow(e, p);
	            if (g.compareTo(TWO) >= 0)
	            {
	                return g;
	            }
	        }

	        return null;
	    }

	    private static void hash(Digest d, byte[] input, byte[] output)
	    {
	        d.update(input, 0, input.length);
	        d.doFinal(output, 0);
	    }

	    private static int getDefaultN(int L)
	    {
	        return L > 1024 ? 256 : 160;
	    }

	    private static void inc(byte[] buf)
	    {
	        for (int i = buf.length - 1; i >= 0; --i)
	        {
	            byte b = (byte)((buf[i] + 1) & 0xff);
	            buf[i] = b;

	            if (b != 0)
	            {
	                break;
	            }
	        }
	    }
	}
}
