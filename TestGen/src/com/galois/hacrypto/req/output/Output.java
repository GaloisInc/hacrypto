package com.galois.hacrypto.req.output;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
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
			return cypherBouncyCastle("AES/CBC/NoPadding", Cipher.ENCRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));

		case "AES/CBC/DEC":
			return cypherBouncyCastle("AES/CBC/NoPadding", Cipher.DECRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));

		case "AES/CFB128/ENC":
			return cypherBouncyCastle("AES/CFB128/NoPadding",
					Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

		case "AES/CFB128/DEC":
			return cypherBouncyCastle("AES/CFB128/NoPadding",
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
			return cypherBouncyCastle("AES/CFB8/NoPadding",
					Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

		case "AES/CFB8/DEC":
			return cypherBouncyCastle("AES/CFB8/NoPadding",
					Cipher.DECRYPT_MODE, inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

		case "AES/ECB/ENC":
			return cypherBouncyCastle("AES/ECB/NoPadding",
					Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
					null, inputs.get(inputOrder[1]));

		case "AES/ECB/DEC":
			return cypherBouncyCastle("AES/ECB/NoPadding",
					Cipher.DECRYPT_MODE, inputs.get(inputOrder[0]),
					null, inputs.get(inputOrder[1]));

		case "AES/OFB/ENC":
			return cypherBouncyCastle("AES/OFB/NoPadding",
					Cipher.ENCRYPT_MODE, inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

		case "AES/OFB/DEC":
			return cypherBouncyCastle("AES/OFB/NoPadding",
					Cipher.DECRYPT_MODE, inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]), inputs.get(inputOrder[2]));

		case "TDES/CBC/ENC":
			return cypherBouncyCastle("DESede/CBC/NoPadding",
					Cipher.ENCRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

		case "TDES/CBC/DEC":
			return cypherBouncyCastle("DESede/CBC/NoPadding",
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
			return cypherBouncyCastle("DESede/CFB8/NoPadding",
					Cipher.ENCRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

		case "TDES/CFB8/DEC":
			return cypherBouncyCastle("DESede/CFB8/NoPadding",
					Cipher.DECRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
			
		case "TDES/CFB64/ENC":
			return cypherBouncyCastle("DESede/CFB64/NoPadding",
					Cipher.ENCRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

		case "TDES/CFB64/DEC":
			return cypherBouncyCastle("DESede/CFB64/NoPadding",
					Cipher.DECRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));
			
		case "TDES/ECB/ENC":
			return cypherBouncyCastle("DESede/ECB/NoPadding",
					Cipher.ENCRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					null, inputs.get(inputOrder[3]));

		case "TDES/ECB/DEC":
			return cypherBouncyCastle("DESede/ECB/NoPadding",
					Cipher.DECRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					null, inputs.get(inputOrder[3]));
			
		case "TDES/OFB/ENC":
			return cypherBouncyCastle("DESede/OFB/NoPadding",
					Cipher.ENCRYPT_MODE, 
					combinedKey(inputs.get(inputOrder[0]),
							    inputs.get(inputOrder[1]),
							    inputs.get(inputOrder[2])), 
					inputs.get(inputOrder[3]), inputs.get(inputOrder[4]));

		case "TDES/OFB/DEC":
			return cypherBouncyCastle("DESede/OFB/NoPadding",
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
			System.err.print("DECRYPT_MODE");
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
	public static byte[] cypherBouncyCastle(String algorithm, int mode,
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
}
