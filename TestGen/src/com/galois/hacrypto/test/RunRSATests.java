package com.galois.hacrypto.test;

import java.io.File;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.Scanner;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Runs a set of RSA2 tests.
 * 
 * @author dmz
 */
public class RunRSATests {
	private static byte[] SEED = "GaloisCAVP".getBytes();
	private static final BouncyCastleProvider BCP = new BouncyCastleProvider();
	private static int HEX = 16;
	private static String MOD_START = "[MOD";
	
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
				case SIGGEN15: runSigGen15(sc); break;
				case SIGVER15: runSigVer15(sc); break;
				default: // this can't happen
			}
			sc.close();
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
			while (!last.toUpperCase().startsWith(MOD_START)) {
				last = sc.nextLine();
			}
			String mod_str = last;
			String[] mod_parts = mod_str.split(" = ");
			int mod = Integer.parseInt(mod_parts[1].substring(0, mod_parts[1].length() - 1));
			int certainty = 128;
			if (mod > 512) {
				certainty = 160;
			}
			if (mod > 1024) {
				certainty = 200;
			}
			System.err.println("mod = " + mod);
			last = "";

			try {
				out.println(mod_str);
				
				// for this test, we read N from the req file and then,
				// N times, generate appropriate RSA keys
				
				last = sc.nextLine();
				while (!last.toUpperCase().startsWith("N")) {
					out.println(last);
					last = sc.nextLine();
				}
				
				String[] line_parts = last.split(" = ");
				int reps = Integer.parseInt(line_parts[1]);
				
				RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
				kpg.init(new RSAKeyGenerationParameters
				    (
				        new BigInteger("10001", 16), // public exponent
				        new SecureRandom(SEED),
				        mod, // key length
				        certainty // certainty
				    ));

				for (int i = 0; i < reps; i++) {
					final AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
					final RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters) kp.getPrivate();
					
					// E, P, Q, N, D
					out.println("e = " + priv.getPublicExponent().toString(HEX));
					out.println("p = " + priv.getP().toString(HEX));
					out.println("q = " + priv.getQ().toString(HEX));
					out.println("n = " + priv.getModulus().toString(HEX));
					out.println("d = " + priv.getExponent().toString(HEX));
					out.println();
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

	private void runSigGen15(final Scanner sc) {
		System.err.println("Running SigGen15 tests");
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last + "\n");
			last = sc.nextLine();
		}
		header.append("\n");
		
		final File out_file = new File(output_dir + File.separator + "SigGen15_186-3.rsp");
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
			String mod_str = last;
			String[] mod_parts = mod_str.split(" = ");
			int mod = Integer.parseInt(mod_parts[1].substring(0, mod_parts[1].length() - 1));
			
			System.err.println("mod = " + mod);
			last = "";
			
			try {
				out.println(mod_str + "\n");
				
				// for this test, we generate a single RSA key pair, output N and E, and
				// then repeatedly read "SHAAlg" and "Msg" lines and sign the Msg 
				// with the specified SHA algorithm
				
				final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BCP);
				kpg.initialize(mod, new SecureRandom(SEED));
				final KeyPair kp = kpg.generateKeyPair();
				final BCRSAPrivateCrtKey priv = (BCRSAPrivateCrtKey) kp.getPrivate();
					
				out.println("n = " + priv.getModulus().toString(HEX));
				out.println("e = " + priv.getPublicExponent().toString(HEX));

				last = sc.nextLine();
				while (sc.hasNextLine() && !last.toUpperCase().startsWith(MOD_START)) {
					while (!last.toUpperCase().startsWith(MOD_START) 
							&& !last.toUpperCase().startsWith("SHAALG")) {
						out.println(last);
						last = sc.nextLine();
					}
					
					String[] line_parts = last.split(" = ");
					String alg = line_parts[1];
	
					while (!last.toUpperCase().startsWith("MSG")) {
						out.println(last);
						last = sc.nextLine();
					}
					
					line_parts = last.split(" = ");
					final byte[] msg = Util.hexStringToByteArray(line_parts[1]);
					
					out.println(last);
					
					try {
						Signature sig = Signature.getInstance(alg + "withRSA", BCP);
						sig.initSign(priv);
						sig.update(msg);
						out.println("S = " + Util.byteArrayToHexString(sig.sign()) + "\n");
					} catch (NoSuchAlgorithmException e) {
						out.println("S = ? (algorithm not available)\n");
					}	
					while (sc.hasNextLine() && !last.toUpperCase().startsWith(MOD_START) 
							&& !last.toUpperCase().startsWith("SHAALG")) {
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

	private void runSigVer15(final Scanner sc) {
		System.err.println("Running SigVer15 tests");
		StringBuilder header = new StringBuilder();
		String last = sc.nextLine();
		while (last.startsWith("#")) {
			header.append(last + "\n");
			last = sc.nextLine();
		}
		header.append("\n");
		
		final File out_file = new File(output_dir + File.separator + "SigVer15_186-3.rsp");
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
			String mod_str = last;
			String[] mod_parts = mod_str.split(" = ");
			int mod = Integer.parseInt(mod_parts[1].substring(0, mod_parts[1].length() - 1));
			
			System.err.println("mod = " + mod);
			last = "";

			try {
				out.println(mod_str);

				// for this test, we repeateedly read an N, then repeatedly 
				// read SHAAlg, E, Msg, and S for that N and attempt to verify 
				// the signature

				while (!last.toUpperCase().startsWith("N")) {
					last = sc.nextLine();
				}

				while (last.toUpperCase().startsWith("N")) {
					out.println(last); 
					out.println();
					
					String[] line_parts = last.split(" = ");
					final BigInteger modulus = new BigInteger(line_parts[1], 16);

					last = "";
					
					while (sc.hasNextLine() && !last.toUpperCase().startsWith(MOD_START) &&
							!last.toUpperCase().startsWith("N")) {
						while (!last.toUpperCase().startsWith("SHAALG")) {
							last = sc.nextLine();
						}

						out.println(last);

						line_parts = last.split(" = ");
						final String alg = line_parts[1]; 

						while (!last.toUpperCase().startsWith("E")) {
							last = sc.nextLine();
							out.println(last);
						}

						line_parts = last.split(" = ");
						final BigInteger exponent = new BigInteger(line_parts[1], 16);

						while (!last.toUpperCase().startsWith("MSG")) {
							last = sc.nextLine();
							out.println(last);
						}

						line_parts = last.split(" = ");
						final byte[] msg = Util.hexStringToByteArray(line_parts[1]);

						while (!last.toUpperCase().startsWith("S")) {
							last = sc.nextLine();
							out.println(last);
						}

						line_parts = last.split(" = ");
						final byte[] signature = Util.hexStringToByteArray(line_parts[1]);

						RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
						KeyFactory factory = KeyFactory.getInstance("RSA", BCP);
						PublicKey pub = factory.generatePublic(spec);

						try {
							Signature sig = Signature.getInstance(alg + "withRSA", BCP);
							sig.initVerify(pub);
							sig.update(msg);
							final boolean result = sig.verify(signature);

							String result_string = "F";
							if (result) {
								result_string = "P";
							}

							out.println("Result = " + result_string);
						} catch (NoSuchAlgorithmException e) {
							out.println("Result = ? (algorithm not available)");
						}

						out.println();

						while (sc.hasNextLine() && !last.toUpperCase().startsWith(MOD_START) 
								&& !last.toUpperCase().startsWith("SHAALG")
								&& !last.toUpperCase().startsWith("N")) {
							last = sc.nextLine();
						}
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
