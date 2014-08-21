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

	public static byte[] getOutput(String algorithm, List<Object> inputs, int[] inputOrder){
		switch (algorithm.toUpperCase()){
		case "SHA256":
			MessageDigest digest = null;
			try {
				digest = MessageDigest.getInstance("SHA-256");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return digest.digest((byte[])inputs.get(inputOrder[0]));//TODO make this safe!
		case "AESCBCENC" :
			Cipher cipher = null;
			try {
				cipher = Cipher.getInstance("AES/CBC/NoPadding");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			SecretKeySpec key = new SecretKeySpec((byte[])inputs.get(inputOrder[0]), "AES");
		    try {
				cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec((byte[])inputs.get(inputOrder[1])));
			} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		    try {
				return cipher.doFinal((byte[])inputs.get(inputOrder[2]));
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		default: throw new RuntimeException("Unknown algorithm: " + algorithm);
		}
		
	}

}
