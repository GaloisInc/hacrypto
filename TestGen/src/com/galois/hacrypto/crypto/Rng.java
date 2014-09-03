package com.galois.hacrypto.crypto;

import javax.crypto.Cipher;

import com.galois.hacrypto.req.output.Output;
import com.galois.hacrypto.test.Util;

public class Rng {

	private byte[] seed;
	private byte[] key;
	private byte[] iv;
	private final String algorithm;

	public Rng(byte[] seed, byte[] key, String algorithm) {
		this.seed = seed.clone();
		this.key = key.clone();
		this.algorithm = algorithm;
		/*
		 * if(this.seed.length != this.key.length){ throw new
		 * RuntimeException("Seed length and key length must match"); }
		 */
		iv = new byte[seed.length];
	}

	// TODO: The FIPS tests force you to expose an extra API
	// the user api would not take dt and instead somehow generate
	// it from the system date time string
	public byte[] nextRandom(byte[] dt) {

		byte[] i = com.galois.hacrypto.req.output.Output.cypherBouncyCastle(
				algorithm + "/CBC/NoPadding", Cipher.ENCRYPT_MODE, key, iv, dt);

		byte[] rand = com.galois.hacrypto.req.output.Output.cypherBouncyCastle(
				algorithm + "/CBC/NoPadding", Cipher.ENCRYPT_MODE, key, iv,
				xor(i, seed));

		this.seed = com.galois.hacrypto.req.output.Output.cypherBouncyCastle(
				algorithm + "/CBC/NoPadding", Cipher.ENCRYPT_MODE, key, iv,
				xor(i, rand));

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
				.hexStringToByteArray("67cdf51d97e9759ad09c2720baf7ac87");
		byte[] dt = Util
				.hexStringToByteArray("0c453f416c0eaf1087835e06e6a23141");
		byte[] seed = Util
				.hexStringToByteArray("80000000000000000000000000000000");
		Rng rng = new Rng(seed, key, "AES");
		String result = Util.byteArraytoHexString(rng.nextRandom(dt));
		if (result.toLowerCase().equals("7c4d77736f0b37068ae4861de69b88ff")) {
			System.out.println("AES128 passed");
		} else {
			System.out.println("AES128 failed, got " + result + ", expected " + 
		                       "7c4d77736f0b37068ae4861de69b88ff");	
		}

		// first test from TDES3 test vector
		key = Util
				.hexStringToByteArray("2f4c67e95db96e2538160e5ef419aecd671645ad89f1388c");
		dt = Util
				.hexStringToByteArray("3703f397fec2bd63");
		seed = Util
				.hexStringToByteArray("8000000000000000");
		rng = new Rng(seed, key, "DESede");
	 	result = Util.byteArraytoHexString(rng.nextRandom(dt));
		if (result.toLowerCase().equals("6e194f8d1a2a468b")) {
			System.out.println("DESede passed");
		} else {
			System.out.println("DESede failed, got " + result + ", expected " + 
		                       "6e194f8d1a2a468b");
		}
	}

}
