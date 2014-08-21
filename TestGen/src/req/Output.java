package req;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Output {

	public static byte[] getOutput(String algorithm, List<byte[]> inputs,
			int[] inputOrder) {
		switch (algorithm.toUpperCase()) {
		case "SHA256":
			MessageDigest digest = null;
			try {
				digest = MessageDigest.getInstance("SHA-256");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return digest.digest(inputs.get(inputOrder[0]));
			
		case "AES/CBC/ENC":
			return AESCBC(Cipher.ENCRYPT_MODE,
					inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));
			
		case "AES/CBC/DEC":
			return AESCBC(Cipher.DECRYPT_MODE,
					inputs.get(inputOrder[0]),
					inputs.get(inputOrder[1]),
					inputs.get(inputOrder[2]));
			
		default:
			throw new RuntimeException("Unknown algorithm: " + algorithm);
		}

	}

	private static byte[] AESCBC(int mode, byte[] seckey, byte[] iv, byte[] msg) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		SecretKeySpec key = new SecretKeySpec(seckey, "AES");
		try {
			cipher.init(mode, key, new IvParameterSpec(iv));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
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
