package com.galois.hacrypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Iterator;
import java.util.List;
import java.util.LinkedList;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Scanner;
import java.util.Set;

import javax.management.RuntimeErrorException;

import org.stringtemplate.v4.ST;
import org.stringtemplate.v4.STErrorListener;
import org.stringtemplate.v4.STGroup;
import org.stringtemplate.v4.STGroupDir;

public class CTests {

	private String[] imports;
	private STGroup stGroup = new STGroupDir("tmp");
	private ST header = stGroup.getInstanceOf("header");
	private ST main = stGroup.getInstanceOf("run_tests");
	private ST makefile = stGroup.getInstanceOf("Makefile");
	private String fileName;
	Random rn = new Random();
	
	
	public CTests(String fileName){
		this.fileName = fileName;
	}
	
	public void writeTestFiles(String outputDirectory){
		
		new File(outputDirectory).mkdirs();
		
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
		scan.nextLine();//move down
		String allImports = scan.nextLine();
		imports = allImports.split("\\s+");
		String ccargs = scan.nextLine();
		makefile.add("ccargs", ccargs);
		
		while(scan.hasNext()){
			makeTests(scan.nextLine(), outputDirectory, testFile.getParentFile());
		}
	}
	
	private void makeXCompare(String primitive, File testDir, String outputDirectory, Scanner scan){
		KAT kat = new KAT(testDir.getPath() + File.separator + scan.next()); 
		/*TODO: is reading a file the right thing here? Could generate the random
		 * things right away. Have to think about multiple languages.
		 */

		ST xCompareST = stGroup.getInstanceOf("Ctests");
		for(String imp : imports){
			xCompareST.add("imports", imp);
		}
	
		ST oneCompare = stGroup.getInstanceOf("CXCompare");
	
		while(scan.hasNext()){
			oneCompare.add("funcs", primitive + "_" + scan.next());
		}
		
		oneCompare.add("outputsize", kat.getOutputSize()/2); //divide by two because it is represented in hex and output size is bytes
		
		Iterator<Entry<KATInput, String>> it = kat.getEntries().iterator();
		int i=0;
		for(Entry<KATInput, String> oneKat : kat.getEntries()){
			String testname = primitive + "_Xcompare_" + i;
			oneCompare.add("testname", testname );
			main.add("testNames", testname);
			header.add("testNames", testname);
	
			oneCompare.add("inputsize", oneKat.getKey().bytes.length);
			oneCompare.add("input", processInput(oneKat.getKey()));
			oneCompare.add("result", "{ " + Test.hexToCUChar(it.next().getValue()) + " }");
			
			
			xCompareST.add("tests", oneCompare.render());
	
			oneCompare.remove("testname");
			oneCompare.remove("inputsize");
			oneCompare.remove("input");
			oneCompare.remove("result");
			i++;
		}
		
		String filename = primitive + "_Xcompare.c";
		makefile.add("cFiles", filename);
		writeSTToOutDir(filename, outputDirectory, xCompareST);
	}
		
	private void makeCompare(String primitive, File testDir, String outputDirectory, Scanner scan){
		int outLength = scan.nextInt();
		int minLength = scan.nextInt();
		int maxLength = scan.nextInt();
		int tests = scan.nextInt();    
		
		ST compareST = stGroup.getInstanceOf("Ctests");
		for(String imp : imports){
			compareST.add("imports", imp);
		}
	
		ST oneCompare = stGroup.getInstanceOf("CCompare");
		oneCompare.add("firstfunc", primitive + "_" + scan.next());
		while(scan.hasNext()){
			oneCompare.add("funcs", primitive + "_" + scan.next());
		}
		
		oneCompare.add("outputsize", outLength);
	
		for(int i=0; i<tests; i++ ){
			String testname = primitive + "_compare_" + i;
			oneCompare.add("testname", testname );
			main.add("testNames", testname);
			header.add("testNames", testname);
	
			int length = rn.nextInt(maxLength - minLength) + minLength;
			oneCompare.add("inputsize", length);
			oneCompare.add("input", randomCString(length));
	
			compareST.add("tests", oneCompare.render());
	
			oneCompare.remove("testname");
			oneCompare.remove("inputsize");
			oneCompare.remove("input");
	
		}
	
		String filename = primitive + "_compare.c";
		makefile.add("cFiles", filename);
		writeSTToOutDir(filename, outputDirectory, compareST);
		 
	}

	private void writeSTToOutDir(String filename, String outputDirectory, ST toWrite){
		File outfile = new File(outputDirectory + File.separator + filename);
		
		try {
			outfile.createNewFile();
		} catch (IOException e) {
			System.err.println("could not create file " + outfile.getAbsolutePath());
			e.printStackTrace();
		}
	
		try {
			toWrite.write(outfile, null);//TODO: figure out what to do for second argument
		} catch (IOException e) {
			System.err.println("Problem writing to file " + outfile.getAbsolutePath());
			e.printStackTrace();
		}
	}
	
	private void makeKAT(String primitive, File testDir, String outputDirectory, Scanner scan){
		KAT kat = new KAT(testDir.getPath() + File.separator + primitive + "_KAT");
		
		while(scan.hasNext()){
			ST impSt = stGroup.getInstanceOf("Ctests");
			for(String imp : imports){
				impSt.add("imports", imp);
			}
			String implementation = scan.next();
			addKATs(primitive, implementation, kat, impSt);
			
			
			String filename = primitive + "_" + implementation + "_" + "KAT.c";
			makefile.add("cFiles", filename);
			writeSTToOutDir(filename, outputDirectory, impSt);
		}
		
		
	}
	
	private String randomCString(int length){
		StringBuilder sb = new StringBuilder("{ ");
		
		for(int i=0; i<length; i++){
			sb.append(rn.nextInt(256));
			if(i < length -1){
				sb.append(", ");
			}
		}
		sb.append(" }");
		return sb.toString();
	}
	
	private void makeTests(String testString, String outputDirectory, File testDir){
		Scanner scan = new Scanner(testString);
		String primitive = scan.next();
		
		String testType = scan.next();
		
		if(testType.equals("KAT")){
			makeKAT(primitive, testDir, outputDirectory, scan);
		}
		else if(testType.equals("Compare")){
			makeCompare(primitive, testDir, outputDirectory, scan);
		}
		if(testType.equals("XCompare")){
			makeXCompare(primitive, testDir, outputDirectory, scan);
		}
		scan.close();
		
		writeFiles(outputDirectory);
	}
	
	private void writeFiles(String outputDirectory){
		copyStaticFiles(outputDirectory);
		writeSTToOutDir("tests.h", outputDirectory, header);
		writeSTToOutDir("run_tests.c", outputDirectory, main);
		writeSTToOutDir("Makefile", outputDirectory, makefile);
	}
	
	private void copyStaticFiles(String dest){
		copyFiles("tmp" + File.separator + "Ccommon_test.c", dest + File.separator + "Ccommon_test.c");
		copyFiles("tmp" + File.separator + "Ccommon_test.h", dest + File.separator + "Ccommon_test.h");
		copyFiles("tmp" + File.separator + "README.md", dest + File.separator + "README.md");

	}
	
	private void copyFiles(String src, String dest){
		Path source = Paths.get(src);
		Path destination = Paths.get(dest);
		try {
			Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING);
		} catch (IOException e) {
			System.err.println("unable to copy file from "  + source.toAbsolutePath() + " to " + destination.toAbsolutePath());
			e.printStackTrace();
		}
	}
	
	private String biteArrayToCString(byte[] bytes){
		StringBuilder sb = new StringBuilder("{ ");
		for(byte byt : bytes){
			sb.append(byt  & 0xFF); //convert to unsigned
			sb.append(" ,");
		}
		sb.deleteCharAt(sb.length()-1); //there'll be an extra comma
		sb.append("}");
		return sb.toString();
	}
	
	
	private String getKiString(KATInput ki){
		if(ki.inputAs.equals("string") && ki.bytes.length < 500){
			return ("\"" + new String( ki.bytes) + "\"");
		}
		else{
			return biteArrayToCString(ki.bytes);
		}
	}
	
	private String processInput(KATInput ki){
		
		if (ki.repeat <= 1) {
			return getKiString(ki);
		}
		
		ST repeat = stGroup.getInstanceOf("repeat");
		repeat.add("repeats", ki.repeat);
		repeat.add("string", getKiString(ki));
		repeat.add("stringlength", ki.bytes.length);
		return repeat.render();
	}
	
	private void addKATs(String primitive, String implementation, KAT kat, ST testST){
		int ct=0;
		for (Entry<KATInput,String> kv : kat.getEntries()){
			ST oneKAT = stGroup.getInstanceOf("CKAT");
			if(kv.getKey().comment != null){
				oneKAT.add("comment", kv.getKey().comment);
			}
			if(kv.getKey().repeat > 1){
				oneKAT.add("malloc", "yup!");
			}
			oneKAT.add("inputsize", kv.getKey().bytes.length * kv.getKey().repeat);
			oneKAT.add("outputsize", kv.getValue().length()/2);
			
			if(kv.getKey().repeat <= 1){
				oneKAT.add("input", processInput(kv.getKey()));
			}
			else{
				oneKAT.add("input", "malloc(sizeof(char) * " + kv.getKey().bytes.length * kv.getKey().repeat + ")");
				oneKAT.add("repeat", processInput(kv.getKey()));
			}
			
			oneKAT.add("answer", Test.hexToCUChar(new String(kv.getValue())));
			
			String funcname = primitive + "_" + implementation;
			String testname = funcname + "_KAT_" + ct ++;
			
			oneKAT.add("testname", testname);
			oneKAT.add("func", funcname);
			
			testST.add("tests", oneKAT.render());
			
			main.add("testNames", testname);
			header.add("testNames", testname);


		}
	}
	
	
	public static void main(String args[]){
		new CTests("test_defs/C_tests").writeTestFiles("../callsha/tests");		
	}
}
