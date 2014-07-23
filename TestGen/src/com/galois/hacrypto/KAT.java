package com.galois.hacrypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.Set;

public class KAT {

	private Map<String, String> KATs = new LinkedHashMap<String, String>();
	
	
	
	private void addkatFromScanner(Scanner scan){
		StringBuilder sb = new StringBuilder();
		boolean first = true;
		do {
			if(first){
				first=false;
			}
			else{
				sb.append("\\n");
			}
			sb.append(scan.nextLine());
		} while (!scan.hasNext("!!!"));
		//read the rest of the line and get rid of whitespaces and leading !!!
		KATs.put(sb.toString(), scan.nextLine().replaceAll("\\s","").substring(3));
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
	
	public Set<Entry<String,String>> getEntries(){
		return KATs.entrySet();
	}
	
}
