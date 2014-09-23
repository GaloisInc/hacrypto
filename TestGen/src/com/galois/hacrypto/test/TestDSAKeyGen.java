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
public class TestDSAKeyGen {
	public static int CERTAINTY = 128;
	
	public static void main(final String[] the_args) throws Exception {
		Scanner sc = new Scanner(new File(the_args[0]));
		BigInteger p = BigInteger.ZERO;
		BigInteger q = BigInteger.ZERO;
		BigInteger g = BigInteger.ZERO;
		BigInteger x = BigInteger.ZERO;
		BigInteger y = BigInteger.ZERO;

		String line = sc.nextLine();
		
		while (sc.hasNextLine()) {
			// first, read p, q, g
			
			while (!line.contains(" = ") || line.startsWith("[")) {
				line = sc.nextLine();
			}
			String[] parts = line.split(" = ");
			p = new BigInteger(parts[1], 16); 
			line = sc.nextLine();
			parts = line.split(" = ");
			q = new BigInteger(parts[1], 16);
			line = sc.nextLine();
			parts = line.split(" = ");
			g = new BigInteger(parts[1], 16); 
			
			System.out.println("Got P/Q/G");
			System.out.println("P = " + p.toString(16));
			System.out.println("Q = " + q.toString(16));
			System.out.println("G = " + g.toString(16) + "\n");
			
			System.out.println("P prime? " + p.isProbablePrime(CERTAINTY));
			System.out.println("Q prime? " + q.isProbablePrime(CERTAINTY));
			
			System.out.println();
			
			// now, read x/y pairs until we run into something else
			
			line = sc.nextLine(); 
			while (line.trim().length() == 0) {
				line = sc.nextLine();
			}
			
			while (line.toUpperCase().startsWith("X")) {
				parts = line.split(" = ");
				x = new BigInteger(parts[1], 16);
				line = sc.nextLine();
				parts = line.split(" = ");
				y = new BigInteger(parts[1], 16); 

				System.out.println("X = " + x.toString(16));
				System.out.println("Y = " + y.toString(16));
				System.out.print("X in correct range: ");
				if (x.compareTo(BigInteger.ZERO) > 0 && x.compareTo(q) < 0) {
					System.out.println("yes");
				} else {
					System.out.println("no");
				}
				System.out.print("Y = G^X mod P: ");
				if (g.modPow(x, p).equals(y)) {
					System.out.println("yes"); 
				} else {
					System.out.println("no");
				}
				System.out.println();
				if (sc.hasNextLine()) {
					line = sc.nextLine();
					while (sc.hasNextLine() && line.trim().length() == 0) {
						line = sc.nextLine();
					}
				}
			}
		}
		
		sc.close();
	}
}
