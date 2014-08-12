package com.galois.hacrypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.Set;

import javax.management.RuntimeErrorException;

//TODO comment lines 
public class KAT {

	private Map<KATInput, String> KATs = new LinkedHashMap<KATInput, String>();
	
	private byte[] parseByteArray(String arrayRep){
		String[] strings = arrayRep.replace("[", "").replace("]", "").split(",");
		byte[] bytes = new byte[strings.length];
		if(strings[0].equals(" ")){
			bytes = new byte[0];	
		}
		else{
			for(int i=0; i<strings.length; i++){
				bytes[i] = Byte.parseByte(strings[i].trim());
			}
		}
		return bytes;
	}
	
	//this works assuming a fixed output size, and returns the size of the first result
	/*public int getOutputSize(){
		return KATs.values().iterator().next().length();
	}*/
	
	//from 
	//http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java/140861#140861
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    if (len %2 != 0){
	    	throw new RuntimeErrorException(new Error("Invalid hex string length. Must be even, is " + len));
	    }
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	//scanner should be at the beginning of a new input output pair
	private void addkatFromScanner(Scanner scan){
		String comment=null;
		if(scan.hasNext("//")){
			comment = scan.nextLine().substring(2);
		}
		
		String katType = scan.next();
		
		
		int repeat = 1;
		if (scan.hasNext("repeat")){
			scan.next(); //burn the repeat
			repeat = scan.nextInt();
		}
		
		byte[] bytes;
		
		if(katType.equals("string")){
			StringBuilder sb = new StringBuilder();
			boolean first = true;
			while(!scan.hasNext("!!!")) {
				sb.append(scan.nextLine());
				if(first){
					first = false;
					sb.delete(0, 1); //we'll have a leading space.
				}
				if(!scan.hasNext("!!!")){
					sb.append("\n");
				}
			}
			bytes = sb.toString().getBytes();
		}
		else if(katType.equals("hex")){
			bytes = hexStringToByteArray(scan.nextLine().replaceAll("\\s",""));
		}
		else if(katType.equals("array")){
			bytes = parseByteArray(scan.nextLine());
		}
		else if(katType.equals("empty")){
			bytes = new byte[0];
			scan.nextLine();
		}
		else{
			throw new RuntimeErrorException(null, "Unsupported KAT type " + katType);
		}
		KATs.put(new KATInput(repeat, bytes, katType, comment), scan.nextLine().replaceAll("\\s","").substring(3)); //remove whitespace and leading !!!
	}
	
	public KAT(int minSize, int maxSize, int testCt, String algorithm) throws NoSuchAlgorithmException{
		Random rand = new Random();
		for(int i=0; i<testCt; i++){
			int size = rand.nextInt(maxSize - minSize) + minSize;
			byte[] bytes = new byte[size];
			rand.nextBytes(bytes);
			MessageDigest digest;
			digest = MessageDigest.getInstance(algorithm);
			byte[] hash = digest.digest(bytes);
			 StringBuilder sb = new StringBuilder();
		    for (byte b : hash) {
		        sb.append(String.format("%02X", b));
		    }
		    KATs.put(new KATInput(1, bytes, "array", "Random test" + i), sb.toString());
		}
	}
	
	
	public KAT(String fileName){
		File testFile = new File(fileName);
		Scanner scan= null;
		try {
			scan = new Scanner(testFile);
		} catch (FileNotFoundException e) {
			System.err.println("Could not find file " + testFile);
			e.printStackTrace();
		}
		while(scan.hasNext()){
			addkatFromScanner(scan);
		}
	}
	
	public Set<Entry<KATInput,String>> getEntries(){
		return KATs.entrySet();
	}
	
	public void toFile(String fileName) throws FileNotFoundException{
		PrintWriter out = new PrintWriter(fileName);
		out.print(this.toString());
		out.close();
	}
	
	//probably not that useful now...
	public String toString(){
		StringBuilder sb = new StringBuilder();
		for(Entry<KATInput,String> e : KATs.entrySet()){
			sb.append(e.getKey().toString());
			sb.append("\n!!! ");
			sb.append(new String(e.getValue()));
			sb.append("\n");
		}
		return sb.toString();
	}
	
	public Entry<String,String> simpleStrings(){
		StringBuilder inSb = new StringBuilder();
		StringBuilder outSb = new StringBuilder();
		for(Entry<KATInput, String> e : KATs.entrySet()){
			inSb.append(e.getKey().simpleInputString());
			inSb.append("\n");
			outSb.append((e.getValue().length())/2);//division because length is string length, not byte length
			outSb.append(" ");
			outSb.append(e.getValue());
			outSb.append("\n");
		}
		return new SimpleEntry<String,String>(inSb.toString(), outSb.toString());
	}
		
}
