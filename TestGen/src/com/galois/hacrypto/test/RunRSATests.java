package com.galois.hacrypto.test;

import java.io.File;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.Scanner;

import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Runs a set of RSA2 tests.
 * 
 * @author dmz
 */
public class RunRSATests {
	private static final BouncyCastleProvider BCP = new BouncyCastleProvider();
	private static int HEX = 16;
	private static String ALG = "ZZ";
	private static String MOD_START = "[mod";
	
	private enum RSATestType {
		KEYGEN_RPP("KeyGen_RandomProbablyPrime3_3.req"),
		SIGGEN15("SigGen15_186-3.req"),
		SIGVER15("SigVer15_186-3.req");

		private final String my_filename; 
		
		private RSATestType(final String the_filename) {
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
	public RunRSATests(final String the_test_dir, final String the_output_dir) {
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
		for (RSATestType test : RSATestType.values()) {
			File tf = new File(test_dir.getPath() + File.separator + test.filename());
			if (tf.exists()) {
				System.err.println("Running tests for " + tf.getPath());
				runTest(test, tf);
			}
		}
	}
	
	private void runTest(final RSATestType the_test, final File the_file) {
		try {
			Scanner sc = new Scanner(the_file);
			switch (the_test) {
				case KEYGEN_RPP: runKeyGenRPP(sc); break;
				default: // this can't happen
			}
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
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
	
	private void runKeyGenRPP(final Scanner sc) {
		System.err.println("Running KeyGenRPP tests");
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last + "\n");
			last = sc.nextLine();
		}
		header.append("\n");
		
		final File out_file = new File(output_dir + File.separator + "KeyGen_RandomProbablyPrime3_3.rsp");
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
			while (!last.startsWith(MOD_START)) {
				last = sc.nextLine();
			}
			String mod_str = last;
			String[] mod_parts = mod_str.split(" = ");
			int mod = Integer.parseInt(mod_parts[1].substring(0, mod_parts[1].length() - 1));
			
			System.err.println("mod = " + mod);
			last = "";
			
			try {
				out.println(mod_str);
				
				// for this test, we read N from the req file and then,
				// N times, generate appropriate RSA keys
				
				last = sc.nextLine();
				while (!last.startsWith("N")) {
					out.println(last);
					last = sc.nextLine();
				}
				
				String[] line_parts = last.split(" = ");
				int reps = Integer.parseInt(line_parts[1]);
				
				final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BCP);

				for (int i = 0; i < reps; i++) {
					kpg.initialize(mod);
					
					final KeyPair kp = kpg.generateKeyPair();
					final BCRSAPrivateCrtKey priv = (BCRSAPrivateCrtKey) kp.getPrivate();
					
					// E, P, Q, N, D
					out.println("E = " + toHexString(priv.getPublicExponent(), mod / 4));
					out.println("P = " + toHexString(priv.getPrimeExponentP(), mod / 8));
					out.println("Q = " + toHexString(priv.getPrimeExponentQ(), mod / 8));
					out.println("N = " + toHexString(priv.getModulus(), mod / 4));
					out.println("D = " + toHexString(priv.getPrivateExponent(), mod / 4));
					out.println();
				}
			} catch (final Exception e) {
				out.close();
				throw new RuntimeException(e);
			}
			
			while (sc.hasNextLine() && !last.startsWith(MOD_START)) {
				last = sc.nextLine();
			}
		}
		
		out.close();
	}

	/*
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
			while (!last.startsWith("[A.")) {
				out.println(last);
				last = sc.nextLine();
			}
			out.println(last);
			String[] words = last.split(" ");
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
		while (!last.startsWith("[A.") && the_scanner.hasNextLine()) {
			while (!last.startsWith(MOD_START)) {
				last = the_scanner.nextLine();
			}
			String mod = last;
			DSATestParams testparams = parseMod(mod);
			
			last = the_scanner.nextLine();
			try {
				the_output.println(mod + "\n");
				
				// we need to read the "Num" line to tell us how many repetitions to do
				
				while (!last.startsWith("Num")) {
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
			while (the_scanner.hasNextLine() && !last.startsWith(MOD_START)
					&& !last.startsWith("[A.")) {
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
		while (!last.startsWith("[A.") && the_scanner.hasNextLine()) {
			while (!last.startsWith(MOD_START)) {
				last = the_scanner.nextLine();
			}
			String mod = last;
			DSATestParams testparams = parseMod(mod);
			
			last = the_scanner.nextLine();
			try {
				the_output.println(mod + "\n");
				
				// we need to read the "Num" line to tell us how many repetitions to do
				
				while (!last.startsWith("Num")) {
					last = the_scanner.nextLine();
				}
				
				String[] line_parts = last.split(" = ");
				int reps = Integer.valueOf(line_parts[1]);

				System.err.println("L=" + testparams.L + ", N=" + testparams.N 
						+ ", alg=" + testparams.alg);

				for (int i = 0; i < reps; i++) {
					// for each repetition, we need to read a P and a Q, then output
					// the resulting G
	
					while (!last.startsWith("P =")) {
						last = the_scanner.nextLine();
					}

					the_output.println(last);

					line_parts = last.split(" = ");
					BigInteger p = new BigInteger(line_parts[1], HEX);
					
					while (!last.startsWith("Q =")) {
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
			while (the_scanner.hasNextLine() && !last.startsWith(MOD_START)
					&& !last.startsWith("[A.")) {
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
		while (!last.startsWith("[A.") && the_scanner.hasNextLine()) {
			while (!last.startsWith(MOD_START)) {
				last = the_scanner.nextLine();
			}
			String mod = last;
			DSATestParams testparams = parseMod(mod);
			
			last = the_scanner.nextLine();
			try {
				the_output.println(mod + "\n");
				
				// we need to read the "Num" line to tell us how many repetitions to do
				
				while (!last.startsWith("Num")) {
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
					while (the_scanner.hasNextLine() && !last.startsWith("P =")) {
						last = the_scanner.nextLine();
					}
					if (!the_scanner.hasNextLine()) {
						continue;
					}
					the_output.println(last);
					line_parts = last.split(" = ");
					BigInteger p = new BigInteger(line_parts[1], HEX);
					
					while (!last.startsWith("Q =")) {
						last = the_scanner.nextLine();
						the_output.println(last);
					}
					
					line_parts = last.split(" = ");
					BigInteger q = new BigInteger(line_parts[1], HEX);

					while (!last.startsWith("domain_parameter_seed =")) {
						last = the_scanner.nextLine();
						the_output.println(last);
					}
					
					line_parts = last.split(" = ");
					byte[] dpseed = Util.hexStringToByteArray(line_parts[1]);
					
					while (!last.startsWith("index =")) {
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
			while (the_scanner.hasNextLine() && !last.startsWith(MOD_START)
					&& !last.startsWith("[A.")) {
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
			while (!last.startsWith(MOD_START)) {
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
					while (!last.startsWith("Msg")) {
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
			
			while (sc.hasNextLine() && !last.startsWith(MOD_START)) {
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
			while (!last.startsWith(MOD_START)) {
				last = sc.nextLine();
			}
			String mod = last;
			DSATestParams testparams = parseMod(mod);
			
			last = sc.nextLine();
			
			try {
				out.println(mod);

				// first, we read the domain parameters P, Q, G
								
				while (!last.startsWith("P =")) {
					out.println(last);
					last = sc.nextLine();
				}
				
				String[] line_parts = last.split(" = ");
				BigInteger p = new BigInteger(line_parts[1], HEX);
				
				while (!last.startsWith("Q =")) {
					out.println(last);
					last = sc.nextLine();
				}
				
				line_parts = last.split(" = ");
				BigInteger q = new BigInteger(line_parts[1], HEX);
				
				while (!last.startsWith("G = ")) {
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
				
				while (sc.hasNextLine() && !last.startsWith(MOD_START)) {
					// read Msg
					out.flush();
					while (!last.startsWith("Msg")) {
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
						while (!last.startsWith("S")) {
							last = sc.nextLine();
						}
						last = "";
						while (sc.hasNextLine() && last.trim().length() == 0) {
							last = sc.nextLine();
						}
						continue;
					}
					
					byte[] msg = Util.hexStringToByteArray(line_parts[1]);
					msg_d.update(msg, 0, msg.length);
					msg_d.doFinal(digested_msg, 0);
					
					// read Y
					while (!last.startsWith("Y")) {
						out.println(last);
						last = sc.nextLine();
					}
					
					line_parts = last.split(" = ");
					final BigInteger y = new BigInteger(line_parts[1], HEX);
					
					// read R
					while (!last.startsWith("R")) {
						out.println(last);
						last = sc.nextLine();
					}
					
					line_parts = last.split(" = ");
					final BigInteger r = new BigInteger(line_parts[1], HEX);

					// read S
					while (!last.startsWith("S")) {
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
			
			while (sc.hasNextLine() && !last.startsWith(MOD_START)) {
				last = sc.nextLine();
			}
		}
		
		out.close();
	}
	
	*/
	public static void main(final String... the_args) {
		if (the_args.length < 2) {
			System.err.println("directories for files must be specified");
			System.exit(1);
		}

		System.err.println("RSA Tests for BouncyCastle Version " + (new BouncyCastleProvider()).getVersion());
		System.err.println("Starting run at " + new Date());
		long startTime = System.currentTimeMillis();

		RunRSATests stf = new RunRSATests(the_args[0], the_args[1]);
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
