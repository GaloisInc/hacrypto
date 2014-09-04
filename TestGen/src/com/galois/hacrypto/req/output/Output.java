package com.galois.hacrypto.req.output;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.galois.hacrypto.crypto.Rng;
import com.galois.hacrypto.test.Util;

public class Output {

	private static final BouncyCastleProvider BCP = new BouncyCastleProvider();

	static {
		Security.addProvider(BCP);
	}
	
	/**
	 * Valid functions are:
	 * <ul>
	 * <li>TBD
	 * </ul>
	 * 
	 * @param algorithm The name of the algorithm.
	 * @param inputs
	 *            possibly out of order superset of the inputs to the algorithm,
	 *            modified by the algorithm for the next iteration
	 * @param inputOrder
	 *            integers pointing to the inputs to the algorithm in order
	 * @return the output of the algorithm on its inputs
	 */
	public static byte[] getMonteCarloOutput(final String algorithm, 
			final List<byte[]> inputs, final int[] inputOrder) {
		/*
		switch (algorithm) {
			case "AES/CBC/ENC":
				return monteCarloAES("CBC", Cipher.ENCRYPT_MODE, inputs, inputOrder);

			case "AES/CBC/DEC":
				return monteCarloAES("CBC", Cipher.DECRYPT_MODE, inputs, inputOrder);

			case "AES/CFB128/ENC":
				return cipherBouncyCastle("AES/CFB128/NoPadding",
						Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
						inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

			case "AES/CFB128/DEC":
				return cipherBouncyCastle("AES/CFB128/NoPadding",
						Cipher.DECRYPT_MODE, inputs.get(inputOrder[0]),
						inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));
	
			case "AES/CFB1/ENC": //TODO this doesn't work! 
				return cypherBouncyCastle("AES/CFB1/NoPadding", Cipher.ENCRYPT_MODE,
				inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
				inputs.get(inputOrder[2]));
				 
			case "AES/CFB1/DEC": 
				return cypherBouncyCastle("AES/CFB1/NoPadding", Cipher.DECRYPT_MODE,
				inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
				inputs.get(inputOrder[2])); 
	
			case "AES/CFB8/ENC":
				return cipherBouncyCastle("AES/CFB8/NoPadding",
						Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
						inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

			case "AES/CFB8/DEC":
				return cipherBouncyCastle("AES/CFB8/NoPadding",
						Cipher.DECRYPT_MODE, inputs.get(inputOrder[0]),
						inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

			case "AES/ECB/ENC":
				return cipherBouncyCastle("AES/ECB/NoPadding",
						Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
						null, inputs.get(inputOrder[1]));

			case "AES/ECB/DEC":
				return cipherBouncyCastle("AES/ECB/NoPadding",
						Cipher.DECRYPT_MODE, inputs.get(inputOrder[0]),
						null, inputs.get(inputOrder[1]));

			case "AES/OFB/ENC":
				return cipherBouncyCastle("AES/OFB/NoPadding",
						Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
						inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

			case "AES/OFB/DEC":
				return cipherBouncyCastle("AES/OFB/NoPadding",
						Cipher.DECRYPT_MODE, inputs.get(inputOrder[0]),
						inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

			case "TDES/CBC/ENC":
				return cipherBouncyCastle("DESede/CBC/NoPadding",
						Cipher.ENCRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

			case "TDES/CBC/DEC":
				return cipherBouncyCastle("DESede/CBC/NoPadding",
						Cipher.DECRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
	
			case "TDES/CFB1/ENC":
				return cypherBouncyCastle("DESede/CFB1/NoPadding",
						Cipher.ENCRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

			case "TDES/CFB1/DEC":
				return cypherBouncyCastle("DESede/CFB1/NoPadding",
						Cipher.DECRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
	
			case "TDES/CFB8/ENC":
				return cipherBouncyCastle("DESede/CFB8/NoPadding",
						Cipher.ENCRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

			case "TDES/CFB8/DEC":
				return cipherBouncyCastle("DESede/CFB8/NoPadding",
						Cipher.DECRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
				
			case "TDES/CFB64/ENC":
				return cipherBouncyCastle("DESede/CFB64/NoPadding",
						Cipher.ENCRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

			case "TDES/CFB64/DEC":
				return cipherBouncyCastle("DESede/CFB64/NoPadding",
						Cipher.DECRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
				
			case "TDES/ECB/ENC":
				return cipherBouncyCastle("DESede/ECB/NoPadding",
						Cipher.ENCRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						null, inputs.get(inputOrder[3]));

			case "TDES/ECB/DEC":
				return cipherBouncyCastle("DESede/ECB/NoPadding",
						Cipher.DECRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						null, inputs.get(inputOrder[3]));
				
			case "TDES/OFB/ENC":
				return cipherBouncyCastle("DESede/OFB/NoPadding",
						Cipher.ENCRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

			case "TDES/OFB/DEC":
				return cipherBouncyCastle("DESede/OFB/NoPadding",
						Cipher.DECRYPT_MODE, 
						combinedKey(inputs.get(inputOrder[0]),
								    inputs.get(inputOrder[1]),
								    inputs.get(inputOrder[2])), 
						inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
				
			case "RNG/AES":
				return rng(inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
						inputs.get(inputOrder[2]), "AES");

			case "RNG/TDES2":
				return rng(
						combinedKey(inputs.get(inputOrder[0]),
								inputs.get(inputOrder[1]),
								inputs.get(inputOrder[0])),
						inputs.get(inputOrder[2]), inputs.get(inputOrder[3]),
						"DESede");

			case "RNG/TDES3":
				return rng(
						combinedKey(inputs.get(inputOrder[0]),
								inputs.get(inputOrder[1]),
								inputs.get(inputOrder[0])),
						inputs.get(inputOrder[2]), inputs.get(inputOrder[3]),
						"DESede");
				
			default:
				throw new RuntimeException("Unknown algorithm for Monte Carlo: " + algorithm);
		}
		*/
		
		if (algorithm.startsWith("AES/")) {
			return monteCarloAES(algorithm, inputs, inputOrder);
		} else if (algorithm.startsWith("TDES/")) {
			return monteCarloDESede(algorithm, inputs, inputOrder);
		} else {
			return new byte[8];
		}
	}
	
	/**
	 * Valid inputs are:
	 * <ul>
	 * <li>SHA1
	 * <li>SHA256
	 * <li>SHA224
	 * <li>SHA384
	 * <li>SHA512
	 * <li>AES/CBC/ENC
	 * <li>AES/CBC/DEC
	 * <li>AES/CFB128/ENC
	 * <li>AES/CFB128/DEC
	 * <li>AES/CFB8/ENC
	 * <li>AES/CFB8/DEC
	 * <li>AES/ECB/ENC
	 * <li>AES/ECB/DEC
	 * <li>AES/OFB/ENC
	 * <li>AES/OFB/DEC
	 * <li>RNG/AES
	 * <li>RNG/TDES2
	 * <li>RNG/TDES3
	 * <li>HMAC
	 * <li>TDES/CBC/ENC
	 * <li>TDES/CBC/DEC
	 * <li>TDES/CFB/ENC
	 * <li>TDES/CFB/DEC
	 * <li>TDES/ECB/ENC
	 * <li>TDES/ECB/DEC
	 * <li>TDES/OFB/INC
	 * <li>TDES/OFB/DEC
	 * <li>
	 * </ul>
	 * 
	 * @param algorithm
	 *            String name of the algorithm.
	 * @param inputs
	 *            possibly out of order superset of the inputs to the algorithm
	 * @param inputOrder
	 *            integers pointing to the inputs to the algorithm in order
	 * @return the output of the algorithm on its inputs
	 */
	public static byte[] getOutput(String algorithm, List<byte[]> inputs,
			int[] inputOrder) {
		switch (algorithm.toUpperCase()) {
		case "SHA256":
			return digestBouncyCastle("SHA-256", inputs.get(inputOrder[0]));

		case "SHA1":
			return digestBouncyCastle("SHA1", inputs.get(inputOrder[0]));

		case "SHA224":
			return digestBouncyCastle("SHA-224", inputs.get(inputOrder[0]));

		case "SHA384":
			return digestBouncyCastle("SHA-384", inputs.get(inputOrder[0]));

		case "SHA512":
			return digestBouncyCastle("SHA-512", inputs.get(inputOrder[0]));

		case "AES/CBC/ENC":
			return cipherBouncyCastle("AES/CBC/NoPadding", Cipher.ENCRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));

		case "AES/CBC/DEC":
			return cipherBouncyCastle("AES/CBC/NoPadding", Cipher.DECRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));

		case "AES/CFB128/ENC":
			return cipherBouncyCastle("AES/CFB128/NoPadding",
					Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

		case "AES/CFB128/DEC":
			return cipherBouncyCastle("AES/CFB128/NoPadding",
					Cipher.DECRYPT_MODE, inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));
/*
		case "AES/CFB1/ENC": //TODO this doesn't work! 
			return cypherBouncyCastle("AES/CFB1/NoPadding", Cipher.ENCRYPT_MODE,
			inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
			inputs.get(inputOrder[2]));
			 
		case "AES/CFB1/DEC": 
			return cypherBouncyCastle("AES/CFB1/NoPadding", Cipher.DECRYPT_MODE,
			inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
			inputs.get(inputOrder[2])); 
*/
		case "AES/CFB8/ENC":
			return cipherBouncyCastle("AES/CFB8/NoPadding",
					Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

		case "AES/CFB8/DEC":
			return cipherBouncyCastle("AES/CFB8/NoPadding",
					Cipher.DECRYPT_MODE, inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

		case "AES/ECB/ENC":
			return cipherBouncyCastle("AES/ECB/NoPadding",
					Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
					null, inputs.get(inputOrder[1]));

		case "AES/ECB/DEC":
			return cipherBouncyCastle("AES/ECB/NoPadding",
					Cipher.DECRYPT_MODE, inputs.get(inputOrder[0]),
					null, inputs.get(inputOrder[1]));

		case "AES/OFB/ENC":
			return cipherBouncyCastle("AES/OFB/NoPadding",
					Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

		case "AES/OFB/DEC":
			return cipherBouncyCastle("AES/OFB/NoPadding",
					Cipher.DECRYPT_MODE, inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

		case "TDES/CBC/ENC":
			return cipherBouncyCastle("DESede/CBC/NoPadding",
					Cipher.ENCRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

		case "TDES/CBC/DEC":
			return cipherBouncyCastle("DESede/CBC/NoPadding",
					Cipher.DECRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
/*
		case "TDES/CFB1/ENC":
			return cypherBouncyCastle("DESede/CFB1/NoPadding",
					Cipher.ENCRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

		case "TDES/CFB1/DEC":
			return cypherBouncyCastle("DESede/CFB1/NoPadding",
					Cipher.DECRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
*/
		case "TDES/CFB8/ENC":
			return cipherBouncyCastle("DESede/CFB8/NoPadding",
					Cipher.ENCRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

		case "TDES/CFB8/DEC":
			return cipherBouncyCastle("DESede/CFB8/NoPadding",
					Cipher.DECRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
			
		case "TDES/CFB64/ENC":
			return cipherBouncyCastle("DESede/CFB64/NoPadding",
					Cipher.ENCRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

		case "TDES/CFB64/DEC":
			return cipherBouncyCastle("DESede/CFB64/NoPadding",
					Cipher.DECRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
			
		case "TDES/ECB/ENC":
			return cipherBouncyCastle("DESede/ECB/NoPadding",
					Cipher.ENCRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					null, inputs.get(inputOrder[3]));

		case "TDES/ECB/DEC":
			return cipherBouncyCastle("DESede/ECB/NoPadding",
					Cipher.DECRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					null, inputs.get(inputOrder[3]));
			
		case "TDES/OFB/ENC":
			return cipherBouncyCastle("DESede/OFB/NoPadding",
					Cipher.ENCRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

		case "TDES/OFB/DEC":
			return cipherBouncyCastle("DESede/OFB/NoPadding",
					Cipher.DECRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
			
		case "RNG/AES":
			return rng(inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]), "AES");

		case "RNG/TDES2":
			return rng(
					combinedKey(inputs.get(inputOrder[0]),
							inputs.get(inputOrder[1]),
							inputs.get(inputOrder[0])),
					inputs.get(inputOrder[2]), inputs.get(inputOrder[3]),
					"DESede");

		case "RNG/TDES3":
			return rng(
					combinedKey(inputs.get(inputOrder[0]),
							inputs.get(inputOrder[1]),
							inputs.get(inputOrder[0])),
					inputs.get(inputOrder[2]), inputs.get(inputOrder[3]),
					"DESede");

		case "HMAC":
			int outlen = ByteBuffer.wrap(inputs.get(inputOrder[0])).getInt();
			return hmacBouncyCastle(outlen, inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));

		default:
			throw new RuntimeException("Unknown algorithm: " + algorithm);
		}

	}

	/**
	 * Combines the supplied 3 keys into a single key containing the 
	 * concatenation of the 3 keys. No length checking is performed.
	 * 
	 * @param key_1 The first key.
	 * @param key_2 The second key.
	 * @param key_3 The third key.
	 * @return the combined key.
	 */
	private static byte[] combinedKey(final byte[] key_1, final byte[] key_2,
			final byte[] key_3) {
		final byte[] result = new byte[key_1.length + key_2.length
				+ key_3.length];
		System.arraycopy(key_1, 0, result, 0, key_1.length);
		System.arraycopy(key_2, 0, result, key_1.length, key_2.length);
		System.arraycopy(key_3, 0, result, key_1.length + key_2.length,
				key_3.length);
		return result;
	}

	/**
	 * Splits the supplied key into three equal-length keys and returns
	 * them in an array. No length checking is performed other than
	 * divisibility by 3.
	 * 
	 * @param key The key.
	 * @return an array of 3 keys.
	 */
	private static byte[][] splitKey(final byte[] key) {
		if (key.length % 3 != 0) {
			throw new IllegalArgumentException(
					"key length must be divisible by 3, was " + key.length);
		}
		
		byte[][] result = new byte[3][key.length / 3];
		for (int i = 0; i < 3; i++) {
			System.arraycopy(key, i * key.length / 3, result[i], 0, key.length / 3);
		}
		
		return result;
	}

	/**
	 * Wrapper function for the {@link Rng} class
	 * @param key
	 *            the secret key
	 * @param dt
	 *            the date time vector
	 * @param seed
	 *            the seed
	 * @param alg
	 *            the java/bouncycastle algorithm to use
	 * @return next random bytes generated by the inputs
	 */
	public static byte[] rng(byte[] key, byte[] dt, byte[] seed, String alg) {
		Rng r = new Rng(seed, key, alg);
		return r.nextRandom(dt).clone();
	}

	/**
	 * @param algorithm
	 *            BouncyCastle algorithm name
	 * @param message
	 *            message to be digested
	 * @return message digest
	 */
	public static byte[] digestBouncyCastle(String algorithm, byte[] message) {
		MessageDigest digest = null;
		try {
			digest = MessageDigest.getInstance(algorithm, BCP);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return digest.digest(message);
	}

	/**
	 * A print to std error of useful information for a cipher state
	 * 
	 * @param algorithm
	 * @param mode
	 * @param seckey
	 * @param iv
	 * @param msg
	 */
	private static void debugPrintCipher(String algorithm, int mode,
			byte[] seckey, byte[] iv, byte[] msg) {
		System.err.println("Algorithm: " + algorithm);
		System.err.print("Mode: ");
		switch (mode) {
		case Cipher.DECRYPT_MODE:
			System.err.println("DECRYPT_MODE");
			break;

		case Cipher.ENCRYPT_MODE:
			System.err.println("ENCRYPT_MODE");

		default:
			System.err.println("UNKNOWN MODE");
		}
		System.err.println("Key length: " + seckey.length + " bytes/ "
				+ seckey.length * 8 + " bits.");
		System.err.println("IV length: " + iv.length + " bytes/ " + iv.length
				* 8 + " bits.");
		System.err.println("Msg length: " + msg.length + " bytes/ "
				+ msg.length * 8 + " bits.");

	}

	/**
	 * @param algorithm
	 *            Bouncy Castle algorithm name
	 * @param mode
	 *            Cipher encrypt or decrypt mode
	 * @param seckey
	 *            Secret key
	 * @param iv
	 *            Initialization Vector
	 * @param msg
	 *            The message to be encrypted or decrypted
	 * @return the msg encrypted/decrypted by the given algorithm
	 */
	public static byte[] cipherBouncyCastle(String algorithm, int mode,
			byte[] seckey, byte[] iv, byte[] msg) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(algorithm, BCP);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		SecretKeySpec key = new SecretKeySpec(seckey, "");
		IvParameterSpec ivp = null;
		if (iv != null) {
			ivp = new IvParameterSpec(iv);
		}
		try {
			cipher.init(mode, key, ivp);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			debugPrintCipher(algorithm, mode, seckey, iv, msg);
			System.err
					.println("If you are having unexpected key size errors, be sure you have installed");
			System.err
					.println("JCE Unlimited Strength Jurisdiction Policy Files");
			e.printStackTrace();
		}
		try {
			return cipher.doFinal(msg);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param algorithm
	 *            Bouncy Castle algorithm name
	 * @param mode
	 *            Cipher encrypt or decrypt mode
	 * @param seckey
	 *            Secret key
	 * @param iv
	 *            Initialization Vector
	 * @return the initialized cipher
	 */
	public static Cipher initCipherBouncyCastle(String algorithm, int mode,
			byte[] seckey, byte[] iv) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(algorithm, BCP);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		SecretKeySpec key = new SecretKeySpec(seckey, "");
		IvParameterSpec ivp = null;
		if (iv != null) {
			ivp = new IvParameterSpec(iv);
		}
		try {
			cipher.init(mode, key, ivp);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			debugPrintCipher(algorithm, mode, seckey, iv, null);
			System.err
					.println("If you are having unexpected key size errors, be sure you have installed");
			System.err
					.println("JCE Unlimited Strength Jurisdiction Policy Files");
			e.printStackTrace();
		}
		return cipher;
	}
	
	/**
	 * Run BouncyCastle HMAC
	 * @param outlen the output length in bytes. This decides which HMAC to run
	 * @param seckey the secret key
	 * @param msg the message being authenticated
	 * @return the MAC
	 */
	public static byte[] hmacBouncyCastle(int outlen, byte[] seckey, byte[] msg) {
		String algorithm;
		switch (outlen) {
		case 20:
			algorithm = "HmacSHA1";
			break;
		case 28:
			algorithm = "HmacSHA224";
			break;
		case 32:
			algorithm = "HmacSHA256";
			break;
		case 48:
			algorithm = "HmacSHA384";
			break;
		case 64:
			algorithm = "HmacSHA512";
			break;
		default:
			throw new RuntimeException("Unknown HMAC output length: " + outlen);
		}
		Mac mac = null;
		SecretKeySpec key = new SecretKeySpec(seckey, algorithm);
		try {
			mac = Mac.getInstance(algorithm, BCP);
			mac.init(key);

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return mac.doFinal(msg);

	}
	
	/**
	 * Runs a "Monte Carlo" test for AES and modifies the inputs in
	 * the input list for the next iteration.
	 * 
	 * @param algorithm The algorithm to use; must start with "AES/".
	 * @param inputs The inputs passed in to the test; the elements of this
	 * list are modified by this method.
	 * @param inputOrder The order of the inputs. 
	 * @return The test output.
	 */
	public static final byte[] monteCarloAES(final String algorithm,
			final List<byte[]> inputs, final int[] inputOrder) {
		if (!algorithm.startsWith("AES/")) {
			throw new RuntimeException("monteCarloAES can only be called for AES tests!");
		}
		String mode = algorithm.substring(4);
		int direction = Integer.MIN_VALUE;		 
		for (String s : new String[]{ "CBC", "CFB1", "CFB8", "CFB128", "ECB", "OFB" }) {
			if (mode.startsWith(s + "/")) {
				if (mode.endsWith("ENC")) {
					direction = Cipher.ENCRYPT_MODE;
				} else if (mode.endsWith("DEC")) {
					direction = Cipher.DECRYPT_MODE;
				} else {
					throw new RuntimeException("invalid algorithm, must end in ENC or DEC");
				}
				mode = s;
				break;
			}
		}
		String bcAlgorithm = "AES/" + mode + "/NoPadding";
		byte[] result = null;
		byte[] key = inputs.get(inputOrder[1]);
		byte[] iv = null;
		byte[] text = inputs.get(inputOrder[2]);
		if (inputs.size() > 3) {
			iv = text;
			text = inputs.get(inputOrder[3]);
		}
		
		switch (mode) {
			case "ECB": 
				byte[] prevResult = null;
				for (int j = 0; j < 1000; j++) {
					result = cipherBouncyCastle(bcAlgorithm, direction, key, null, text);
					prevResult = text;
					text = result;
				}
				// modified key depends on key length
				byte[] newKeyXor = new byte[key.length];
				switch (key.length * 8) {
					case 128:
						newKeyXor = result;
						break;
				
					case 192:
						System.arraycopy(prevResult, 8, newKeyXor, 0, 8);
						System.arraycopy(result, 0, newKeyXor, 8, 16);
						break;
						
					case 256:
						System.arraycopy(prevResult, 0, newKeyXor, 0, 16);
						System.arraycopy(result, 0, newKeyXor, 16, 16);
						break;
						
					default:
						throw new RuntimeException("bad key length for AES Monte Carlo: " + key.length);
				}
				key = Util.xor(key, newKeyXor);
				inputs.set(inputOrder[1], key);
				inputs.set(inputOrder[2], text);
				break;
				
			case "CBC":
			case "OFB":
			case "CFB128":
				prevResult = null;
				// first iteration of CBC is different
				Cipher cipher = initCipherBouncyCastle(bcAlgorithm, direction, key, iv);
				result = cipher.update(text);
				text = iv;
				for (int j = 1; j < 1000; j++) {
					prevResult = result;
					result = cipher.update(text);
					text = prevResult;
				}
				// modified key depends on key length
				newKeyXor = new byte[key.length];
				switch (key.length * 8) {
					case 128:
						newKeyXor = result;
						break;
				
					case 192:
						System.arraycopy(prevResult, 8, newKeyXor, 0, 8);
						System.arraycopy(result, 0, newKeyXor, 8, 16);
						break;
						
					case 256:
						System.arraycopy(prevResult, 0, newKeyXor, 0, 16);
						System.arraycopy(result, 0, newKeyXor, 16, 16);
						break; 
						
					default:
						throw new RuntimeException("bad key length for AES Monte Carlo: " + key.length);
				}
				key = Util.xor(key, newKeyXor);
				inputs.set(inputOrder[1], key);
				inputs.set(inputOrder[2], result);
				inputs.set(inputOrder[3], prevResult);
				break;
				
			case "CFB8":
				byte[][] prevResults = new byte[1001][];
				byte[][] prevTexts = new byte[1001][];
				
				prevTexts[0] = text;
				
				// first iteration of CFB8 is different
				cipher = initCipherBouncyCastle(bcAlgorithm, direction, key, iv);
				prevResults[0] = cipher.update(prevTexts[0]);
				prevTexts[1] = new byte[] { iv[0] };
				
				for (int j = 1; j < 1000; j++) {
					prevResults[j] = cipher.update(prevTexts[j]);
					if (j < 16) {
						prevTexts[j + 1] = new byte[] { iv[j] };
					} else {
						prevTexts[j + 1] = prevResults[j - 16];
					}
				}
				
				final int ceiling = 999;
				result = prevResults[ceiling];
				text = prevResults[ceiling - 16];
				// modified key depends on key length
				newKeyXor = new byte[key.length];
				for (int i = 0; i < key.length; i++) {
					newKeyXor[i] = prevResults[ceiling - (key.length - 1) + i][0];
				}
				key = Util.xor(key, newKeyXor);
				for (int i = 0; i < 16; i++) {
					iv[i] = prevResults[ceiling - 15 + i][0];
				}
				
				inputs.set(inputOrder[1], key);
				inputs.set(inputOrder[2], iv);
				inputs.set(inputOrder[3], text);
				break;
				
			case "CFB1":
				// BouncyCastle doesn't support CFB1, but if it did, the code for generating
				// output would look a lot like the CFB8 code
				
			default:
				throw new IllegalArgumentException("invalid algorithm for AES Monte Carlo: " + algorithm);
		}
		return result;
	}
	
	/**
	 * Runs a "Monte Carlo" test for Triple-DES and modifies the inputs in
	 * the input list for the next iteration.
	 * 
	 * @param algorithm The algorithm to use; must start with "TDES/".
	 * @param inputs The inputs passed in to the test; the elements of this
	 * list are modified by this method.
	 * @param inputOrder The order of the inputs. 
	 * @return The test output.
	 */
	public static final byte[] monteCarloDESede(final String algorithm,
			final List<byte[]> inputs, final int[] inputOrder) {
		if (!algorithm.startsWith("TDES/")) {
			throw new RuntimeException("monteCarloTDES can only be called for TDES tests!");
		}
		String mode = algorithm.substring(5);
		int direction = Integer.MIN_VALUE;		 
		for (String s : new String[]{ "CBC", "CFB1", "CFB8", "CFB128", "ECB", "OFB" }) {
			if (mode.startsWith(s + "/")) {
				if (mode.endsWith("ENC")) {
					direction = Cipher.ENCRYPT_MODE;
				} else if (mode.endsWith("DEC")) {
					direction = Cipher.DECRYPT_MODE;
				} else {
					throw new RuntimeException("invalid algorithm, must end in ENC or DEC");
				}
				mode = s;
				break;
			}
		}
		String bcAlgorithm = "DESede/" + mode + "/NoPadding";
		
		byte[] result = null;
		byte[] key1 = inputs.get(inputOrder[0]);
		byte[] key2 = inputs.get(inputOrder[1]);
		byte[] key3 = inputs.get(inputOrder[2]);
		byte[] iv = null;
		byte[] text = inputs.get(inputOrder[3]);
		if (inputs.size() > 4) {
			iv = text;
			text = inputs.get(inputOrder[4]);
		}
		
		switch (mode) {
			case "ECB": 
				byte[] combinedKey = combinedKey(key1, key2, key3);
				byte[] prevResult = null, prevPrevResult = null;
				for (int j = 0; j < 10000; j++) {
					result = cipherBouncyCastle(bcAlgorithm, direction, combinedKey, null, text);
					prevPrevResult = prevResult;
					prevResult = text;
					text = result;
				}
				// modified key depends on keying type
				
				byte[] newKey1 = Util.xor(key1, result); 
				byte[] newKey2 = null, newKey3 = null;
				
				if (Arrays.equals(key1, key2)) {
					newKey2 = Util.xor(key2, result);
				} else {
					newKey2 = Util.xor(key2, prevResult);
				}
				
				if (Arrays.equals(key1, key3)) {
					newKey3 = Util.xor(key3, result);
				} else {
					newKey3 = Util.xor(key3, prevPrevResult);
				}
				
				Util.adjustParity(newKey1);
				Util.adjustParity(newKey2);
				Util.adjustParity(newKey3);
				
				inputs.set(inputOrder[0], newKey1);
				inputs.set(inputOrder[1], newKey2);
				inputs.set(inputOrder[2], newKey3);
				inputs.set(inputOrder[3], result);
				break;
				
			case "CBC":
				byte[][] cvs = new byte[10001][];
				byte[][] ps = new byte[10001][];
				byte[][] cs = new byte[10001][];
				
				combinedKey = combinedKey(key1, key2, key3);
				Cipher cipher = initCipherBouncyCastle(bcAlgorithm, direction, combinedKey, iv);
				cvs[0] = iv;
				ps[0] = text;
				
				for (int j = 0; j < 10000; j++) {
					cs[j] = cipher.update(ps[j]);
					if (j == 0) {
						ps[1] = cvs[0];
					} else {
						ps[j + 1] = cs[j - 1];
					}
					cvs[j + 1] = cs[j];
				}
				
				// modified key depends on keying type
				
				newKey1 = Util.xor(key1, cs[9999]); 
				
				if (Arrays.equals(key1, key2)) {
					newKey2 = Util.xor(key2, cs[9999]);
				} else {
					newKey2 = Util.xor(key2, cs[9998]);
				}
				
				if (Arrays.equals(key1, key3)) {
					newKey3 = Util.xor(key3, cs[9999]);
				} else {
					newKey3 = Util.xor(key3, cs[9997]);
				}
				
				Util.adjustParity(newKey1);
				Util.adjustParity(newKey2);
				Util.adjustParity(newKey3);
				
				inputs.set(inputOrder[0], newKey1);
				inputs.set(inputOrder[1], newKey2);
				inputs.set(inputOrder[2], newKey3);
				inputs.set(inputOrder[3], cs[9999]);
				inputs.set(inputOrder[4], cs[9998]);
				result = cs[9999];
				break;
				
						
			case "OFB":
				byte[][] texts = new byte[10001][];
				byte[][] is = new byte[10001][];
				byte[][] os = new byte[10001][];
				byte[][] results = new byte[10001][];
				
				combinedKey = combinedKey(key1, key2, key3);
			    cipher = initCipherBouncyCastle(bcAlgorithm, direction, combinedKey, iv);
				is[0] = iv;
				texts[0] = text;
				
				for (int j = 0; j < 10000; j++) {
					os[j] = cipher.update(is[j]);
					results[j] = Util.xor(os[j], texts[j]);
					texts[j + 1] = is[j];
					is[j + 1] = os[j];
				}
				
				// modified key depends on keying type
				
				newKey1 = Util.xor(key1, results[9999]); 
				
				if (Arrays.equals(key1, key2)) {
					newKey2 = Util.xor(key2, results[9999]);
				} else {
					newKey2 = Util.xor(key2, results[9998]);
				}
				
				if (Arrays.equals(key1, key3)) {
					newKey3 = Util.xor(key3, results[9999]);
				} else {
					newKey3 = Util.xor(key3, results[9997]);
				}
				
				Util.adjustParity(newKey1);
				Util.adjustParity(newKey2);
				Util.adjustParity(newKey3);
				
				inputs.set(inputOrder[0], newKey1);
				inputs.set(inputOrder[1], newKey2);
				inputs.set(inputOrder[2], newKey3);
				inputs.set(inputOrder[3], os[9999]);
				inputs.set(inputOrder[4], Util.xor(text, is[9999]));
				result = results[9999];
				break;

			case "CFB128":
			default:
				throw new IllegalArgumentException("invalid algorithm for DES Monte Carlo: " + algorithm);
		}
		return result;
	}
}
