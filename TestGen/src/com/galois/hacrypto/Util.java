package com.galois.hacrypto;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Random;

import javax.management.RuntimeErrorException;

import org.stringtemplate.v4.ST;

public class Util {

	public static final Random rand = new Random();

	/**
	 * Same as {@link Util#writeStringToOutDir(String, String, String)} but uses the
	 * built in file writing of a stringtemplate
	 * 
	 * @param filename
	 *            name of the file to be created/overwritten
	 * @param outputDirectory
	 *            directory to write the file in
	 * @param toWrite
	 *            StringTemplate to render to a file
	 */
	public static void writeSTToOutDir(String filename, String outputDirectory,
			ST toWrite) {
		File outfile = new File(outputDirectory + File.separator + filename);
	
		try {
			outfile.createNewFile();
		} catch (IOException e) {
			System.err.println("could not create file "
					+ outfile.getAbsolutePath());
			e.printStackTrace();
		}
	
		try {
			toWrite.write(outfile, null);// TODO: figure out what to do for
											// second argument
		} catch (IOException e) {
			System.err.println("Problem writing to file "
					+ outfile.getAbsolutePath());
			e.printStackTrace();
		}
	}

	/**
	 * @param filename
	 *            name of the file to be created/overwritten
	 * @param outputDirectory
	 *            directory to write the file in
	 * @param toWrite
	 *            String to be written to the file
	 */
	public static void writeStringToOutDir(String filename,
			String outputDirectory, String toWrite) {
		File outfile = new File(outputDirectory + File.separator + filename);
		try {
			outfile.createNewFile();
		} catch (IOException e) {
			System.err.println("could not create file "
					+ outfile.getAbsolutePath());
			e.printStackTrace();
		}
	
		try {
			PrintWriter out = new PrintWriter(outfile);
			out.print(toWrite);
			out.close();
		} catch (IOException e) {
			System.err.println("Problem writing to file "
					+ outfile.getAbsolutePath());
			e.printStackTrace();
		}
	}

	/**
	 * from <a href =
	 * http://stackoverflow.com/questions/140131/convert-a-string-
	 * representation-of-a-hex-dump-to-a-byte-array-using-java/140861#140861>
	 * this stackoverflow post </a>
	 * 
	 * @param s
	 *            String representation of a hedicamal number. Method will throw
	 *            an exception if the string has odd length
	 * @return Byte array represented by s
	 */
	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		if (len % 2 != 0) {
			throw new RuntimeErrorException(new Error(
					"Invalid hex string length. Must be even, is " + len));
		}
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
					.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	/**
	 * @param arrayRep
	 *            comma separated string of base 10 bytes. Arrays.toString() of
	 *            a byte array will create valid input to this method
	 * @return byte array represented by arrayRep
	 */
	static byte[] parseByteArray(String arrayRep) {
		String[] strings = arrayRep.replace("[", "").replace("]", "")
				.split(",");
		byte[] bytes = new byte[strings.length];
		if (strings[0].equals(" ")) {
			bytes = new byte[0];
		} else {
			for (int i = 0; i < strings.length; i++) {
				bytes[i] = Byte.parseByte(strings[i].trim());
			}
		}
		return bytes;
	}

	/**
	 * @param bytes
	 * @return String containing a hex representation of the byte array
	 */
	public static String byteArraytoHexString(byte[] bytes){
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X", b));
		}
		return sb.toString();
	}

}
