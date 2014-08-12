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
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Scanner;
import java.util.Set;

import javax.management.RuntimeErrorException;

import org.stringtemplate.v4.ST;
import org.stringtemplate.v4.STErrorListener;
import org.stringtemplate.v4.STGroup;
import org.stringtemplate.v4.STGroupDir;
//TODO Could this be one generic class that picks the same template?
//     can templates be written so they all work on the same thing?
public class CTests {

	private String[] imports;
	private STGroup stGroup = new STGroupDir("tmp");
	private ST header = stGroup.getInstanceOf("header");
	private ST main = stGroup.getInstanceOf("run_tests");
	private ST makefile = stGroup.getInstanceOf("Makefile");
	
	private Test test;
	private File outDir;
	
	public void writeTestFiles(File outDir, File inDir, Test test){
		this.outDir = new File(outDir.getPath() + File.separator + "C_tests");
		this.outDir.mkdirs();
		this.test = test;
		File testFile = new File(inDir.getPath() + File.separator + "C_tests");
		
		Scanner scan= null;
		try {
			scan = new Scanner(testFile);
		} catch (FileNotFoundException e) {
			System.err.println("Could not find file " + testFile);
			e.printStackTrace();
		}
		
		String allImports = scan.nextLine();
		imports = allImports.split("\\s+");
		String ccargs = scan.nextLine();
		makefile.add("ccargs", ccargs);
		
		while(scan.hasNext()){
			makeTests(scan.nextLine());
		}
	}

	private void makeCKAT(String primitive, List<String> libs){
		KAT kat = test.getKAT(primitive);
		for(String lib: libs){
			ST impSt = stGroup.getInstanceOf("Ctests");
			for(String imp : imports){
				impSt.add("imports", imp);
			}
			addKATs(primitive, lib, kat, impSt);
			
			String filename = primitive + "_" + lib + "_" + "KAT.c";
			makefile.add("cFiles", filename);
			Test.writeSTToOutDir(filename, outDir.getPath(), impSt);
		}		
	}
	
	private void makeTests(String testString){
		Scanner scan = new Scanner(testString);
		String primitive = scan.next();
		LinkedList<String> libs = new LinkedList<String>();
		while(scan.hasNext()){
			libs.add(scan.next());
		}
		
		if(test.getKAT(primitive)!=null){
			makeCKAT(primitive, libs);
		}
		
		if(test.getTestFile(primitive) != null){
			makeCompare(primitive, libs);
		}
		scan.close();
		
		writeFiles();
	}
	
	private void makeCompare(String primitive, LinkedList<String> libs) {
		ST compareST = stGroup.getInstanceOf("Ctests");
		
		for(String imp : imports){
			compareST.add("imports", imp);
		}
	
		ST oneCompare = stGroup.getInstanceOf("CCompare");
		
		oneCompare.add("algorithm", primitive);
		oneCompare.add("funcct", libs.size());
		for(String lib : libs){
			oneCompare.add("funcs", primitive + "_" + lib);
		}
		
		compareST.add("tests", oneCompare.render());
		
		String filename = primitive + "_compare.c";
		makefile.add("cFiles", filename);
		main.add("testNames", primitive + "_compare");
		header.add("testNames", primitive + "_compare");
		Test.writeSTToOutDir(filename, outDir.getPath(), compareST);
	
	}

	private void writeFiles(){
		copyStaticFiles(outDir.getPath());
		Test.writeSTToOutDir("tests.h", outDir.getPath(), header);
		Test.writeSTToOutDir("run_tests.c", outDir.getPath(), main);
		Test.writeSTToOutDir("Makefile", outDir.getPath(), makefile);
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
	
}
