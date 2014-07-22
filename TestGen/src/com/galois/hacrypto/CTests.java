package com.galois.hacrypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.List;
import java.util.LinkedList;
import java.util.Scanner;

import javax.management.RuntimeErrorException;

import org.stringtemplate.v4.ST;
import org.stringtemplate.v4.STGroup;
import org.stringtemplate.v4.STGroupDir;

public class CTests {

	public List<String> testNames = new LinkedList<String>();
	public List<CKAT> katTests = new LinkedList<CKAT>();
	
	public void addKat(String input, String expectedOutput, String primitive, String implementation, String testname){
		katTests.add(new CKAT(input, expectedOutput, primitive, implementation, testname));
		testNames.add(testname);
	}

		
	private void katsFromScanner(Scanner scan){
		String protocol = scan.next();
		String implementations = scanner
		while (scan.hasNext()){
			addKat(input, expectedOutput, primitive, implementation, testname);
		}
	}
	
	public CTests(String fileName){
		File testFile = new File(fileName);
		Scanner scan= null;
		try {
			scan = new Scanner(testFile);
		} catch (FileNotFoundException e) {
			System.err.println("Could not find file " + testFile);
			e.printStackTrace();
		}
		
		String language = scan.next();
		
		/*switch (language) {
		case "C": break;
		default: throw new RuntimeErrorException(null, "Language " + language + "  not implemented");
		}*/
		//not going to check this now, we'll assume something higher up will pass it down correctly... maybe it'll
		//even give us the scanner...
		
		String testType = scan.next();
		switch (testType){
		case "KAT": katsFromScanner(scan); break;
		default: throw new RuntimeErrorException(null, "Test " + testType + "  not implemented");
		}
	}
	
	public String toString(){
		STGroup stGroup = new STGroupDir("tmp");
		ST testsTemplate = stGroup.getInstanceOf("Ctests");
		
		testsTemplate.add("imports", "callsha.h");
		for(CKAT ckat : katTests){
			testsTemplate.add("KATtests", ckat.toString());
		}
		for(String name : testNames){
			testsTemplate.add("testNames", name);
		}
		return testsTemplate.render();
	}
	
	public static void main(String args[]){
		CTests tests = new CTests();
		tests.addKat("The quick brown fox jumps over the lazy dog",
				"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
				"SHA256", "VST", "test0");
				
		System.out.println(tests);
	}
}
