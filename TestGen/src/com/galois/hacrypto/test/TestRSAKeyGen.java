package com.galois.hacrypto.test;

import java.io.File;
import java.math.BigInteger;
import java.util.Scanner;

/**
 * Reads a file and tests the P and Q values specified in it for primality.
 * This is primarily useful for RSA tests.
 * 
 * @author dmz
 */
public class TestRSAKeyGen {
	public static int CERTAINTY = 200;
	
	public static void main(final String[] the_args) throws Exception {
		Scanner sc = new Scanner(new File(the_args[0]));
		BigInteger e = BigInteger.ZERO;
		BigInteger p = BigInteger.ZERO;
		BigInteger q = BigInteger.ZERO;
		BigInteger n = BigInteger.ZERO;
		BigInteger d = BigInteger.ZERO;

		String line = sc.nextLine();
		
		while (sc.hasNextLine()) {
			// first, read e, p, q, n, d
			
			while (!line.contains(" = ") || line.startsWith("[")) {
				line = sc.nextLine();
			}
			String[] parts = line.split(" = ");
			e = new BigInteger(parts[1], 16); 
			line = sc.nextLine();
			parts = line.split(" = ");
			p = new BigInteger(parts[1], 16);
			line = sc.nextLine();
			parts = line.split(" = ");
			q = new BigInteger(parts[1], 16); 
			line = sc.nextLine();
			parts = line.split(" = ");
			n = new BigInteger(parts[1], 16); 			
			line = sc.nextLine();
			parts = line.split(" = ");
			d = new BigInteger(parts[1], 16); 
			
			System.out.println("Got key values:");
			System.out.println("e = " + e.toString(16));
			System.out.println("p = " + p.toString(16));
			System.out.println("q = " + q.toString(16));
			System.out.println("n = " + n.toString(16));
			System.out.println("d = " + d.toString(16));
			
			System.out.println("e prime? " + e.isProbablePrime(CERTAINTY));
			System.out.println("p prime? " + p.isProbablePrime(CERTAINTY));
			System.out.println("q prime? " + q.isProbablePrime(CERTAINTY));
			BigInteger pq = p.multiply(q);
			System.out.println("n = pq? " + n.equals(pq));
			BigInteger pm1 = p.subtract(BigInteger.ONE);
			BigInteger qm1 = q.subtract(BigInteger.ONE);
			BigInteger mod = pm1.multiply(qm1);
			System.out.println("d = e inverse mod ((p - 1)(q - 1))? " + 
								d.equals(e.modInverse(mod)));
			BigInteger lcm = mod.divide(pm1.gcd(qm1));
			System.out.println("d = e inverse mod (LCM(p - 1, q - 1))? " + 
								d.equals(e.modInverse(lcm)));
			System.out.println();
			
			// try encrypting and decrypting with the key
			
			byte[] test = new byte[256];
			for (int i = 0; i < 256; i++) {
				test[i] = (byte) (i + 1);
			}
			
			System.err.println();
			
			// now, read lines until we run into another line with an equals sign 
			
			line = sc.nextLine(); 
			while (sc.hasNextLine() && !line.contains(" = ")) {
				line = sc.nextLine();
			}
		}
		
		sc.close();
	}
}
