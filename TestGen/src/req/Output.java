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

public class Output {

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

	private static byte[] digestBouncyCastle(String algorithm, byte[] message) {
		Security.addProvider(new BouncyCastleProvider());
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

	private static void debugPrintCyphter(String algorithm, int mode,
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
			debugPrintCyphter(algorithm, mode, seckey, iv, msg);
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
