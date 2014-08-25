package req;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * @author jdodds
 *
 */
/**
 * @author jdodds
 *
 */
/**
 * @author jdodds
 *
 */
public class Output {

	/**
	 * Valid inputs are: SHA1 SHA256 SHA224 SHA384 SHA512
	 * AES/CBC/ENC AES/CBC/DEC AES/CFB128/ENC AES/CFB128/DEC
	 * AES/CFB8/ENC AES/CFB8/DEC AES/ECB/ENC AES/ECB/DEC
	 * AES/OFB/ENC AES/OFB/DEC
	 * @param algorithm  String name of the algorithm.
	 * @param inputs possibly out of order superset of the inputs to the algorithm
	 * @param inputOrder integers pointing to the inputs to the algorithm in order
	 * @return
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
			return cypherBouncyCastle("AES/CFB128/NoPadding", Cipher.ENCRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));
			
		case "AES/CFB128/DEC":
			return cypherBouncyCastle("AES/CFB128/NoPadding", Cipher.DECRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));
			
		/*case "AES/CFB1/ENC": //TODO this doesn't work!
			return cypherBouncyCastle("AES/CFB128/NoPadding", Cipher.ENCRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));
			
		case "AES/CFB1/DEC":
			return cypherBouncyCastle("AES/CFB128/NoPadding", Cipher.DECRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));*/
			
		case "AES/CFB8/ENC":
			return cypherBouncyCastle("AES/CFB8/NoPadding", Cipher.ENCRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));
			
		case "AES/CFB8/DEC":
			return cypherBouncyCastle("AES/CFB8/NoPadding", Cipher.DECRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));
			
		case "AES/ECB/ENC":
			return cypherBouncyCastle("AES/CFB8/NoPadding", Cipher.ENCRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));
			
		case "AES/ECB/DEC":
			return cypherBouncyCastle("AES/CFB8/NoPadding", Cipher.DECRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));
			
		case "AES/OFB/ENC":
			return cypherBouncyCastle("AES/CFB8/NoPadding", Cipher.ENCRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));
			
		case "AES/OFB/DEC":
			return cypherBouncyCastle("AES/CFB8/NoPadding", Cipher.DECRYPT_MODE,
					inputs.get(inputOrder[0]), inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));
			
		default:
			throw new RuntimeException("Unknown algorithm: " + algorithm);
		}

	}
	
	static{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * @param algorithm BouncyCastle algorithm name
	 * @param message message to be digested
	 * @return message digest
	 */
	private static byte[] digestBouncyCastle(String algorithm, byte[] message) {
		MessageDigest digest = null;
		try {
			try {
				digest = MessageDigest.getInstance(algorithm, "BC");
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return digest.digest(message);
	}

	/**
	 * A print to std error of useful information for a cipher state
	 * @param algorithm
	 * @param mode
	 * @param seckey
	 * @param iv
	 * @param msg
	 */
	private static void debugPrintCipher(String algorithm, int mode,
			byte[] seckey, byte[] iv, byte[] msg){
		System.err.println("Algorithm: " + algorithm);
		System.err.print("Mode: ");
		switch (mode){
		case Cipher.DECRYPT_MODE:
			System.err.print("DECRYPT_MODE");
			break;
			
		case Cipher.ENCRYPT_MODE:
			System.err.println("ENCRYPT_MODE");
			
		default:
			System.err.println("UNKNOWN MODE");				
		}
		System.err.println("Key length: " + seckey.length + " bytes/ " + seckey.length * 8 + " bits.");
		System.err.println("IV length: " + iv.length + " bytes/ " + iv.length * 8 + " bits.");
		System.err.println("Msg length: " + msg.length + " bytes/ " + msg.length * 8 + " bits.");
		
	}
	
	/**
	 * @param algorithm Bouncy Castle algorithm name
	 * @param mode Cipher encrypt or decrypt mode
	 * @param seckey Secret key
	 * @param iv Initialization Vector
	 * @param msg The message to be encrypted or decrypted
	 * @return
	 */
	private static byte[] cypherBouncyCastle(String algorithm, int mode,
			byte[] seckey, byte[] iv, byte[] msg) {
		Security.addProvider(new BouncyCastleProvider());
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(algorithm, new BouncyCastleProvider());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException  e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		
		SecretKeySpec key = new SecretKeySpec(seckey,"");
		try {
			cipher.init(mode, key, new IvParameterSpec(iv));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			debugPrintCipher(algorithm, mode, seckey, iv, msg);
			System.err.println("If you are having unexpected key size errors, be sure you have installed");
			System.err.println("JCE Unlimited Strength Jurisdiction Policy Files");
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

}
