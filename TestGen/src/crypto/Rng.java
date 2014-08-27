package crypto;

import javax.crypto.Cipher;

import com.galois.hacrypto.Util;

public class Rng {

	private byte[] seed;
	private byte[] key;
	private byte[] iv;

	public Rng(byte[] seed, byte[] key) {
		this.seed = seed;
		this.key = key;
		this.iv = new byte[key.length];
	}

	// TODO: The FIPS tests force you to expose an extra API
	// the user api would not take dt and instead somehow generate
	// it from the sytem date time string
	public byte[] nextRandom(byte[] dt) {

		byte[] i = req.Output.cypherBouncyCastle("AES/CBC/NoPadding",
				Cipher.ENCRYPT_MODE, key, iv, dt);

		byte[] rand = req.Output.cypherBouncyCastle("AES/CBC/NoPadding",
				Cipher.ENCRYPT_MODE, key, iv, xor(i, seed));

		this.seed = req.Output.cypherBouncyCastle("AES/CBC/NoPadding",
				Cipher.ENCRYPT_MODE, key, iv, xor(i, rand));

		return rand;
	}

	/**
	 * Compute the bitwise XOR of two arrays of bytes. The arrays have to be of
	 * same length. No length checking is performed.
	 * 
	 * @param x1
	 *            the first array
	 * @param x2
	 *            the second array
	 * @return x1 XOR x2
	 */
	public static byte[] xor(byte[] x1, byte[] x2) {
		byte[] out = new byte[x1.length];

		for (int i = x1.length - 1; i >= 0; i--) {
			out[i] = (byte) (x1[i] ^ x2[i]);
		}
		return out;
	}

	public static void main(String args[]) {
		// first test from AES128 test vector
		byte[] key = Util
				.hexStringToByteArray("7213395b28586fe64026056638110b3c");
		byte[] dt = Util
				.hexStringToByteArray("947529f603edb0cf6927f65edbbbc593");
		byte[] seed = Util
				.hexStringToByteArray("80000000000000000000000000000000");
		Rng rng = new Rng(seed, key);
		System.out.println(Util.byteArraytoHexString(rng.nextRandom(dt)));
	}

}
