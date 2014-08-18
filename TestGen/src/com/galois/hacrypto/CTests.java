package com.galois.hacrypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Scanner;

import javax.management.RuntimeErrorException;

import org.stringtemplate.v4.ST;

/**
 * Generates C tests for known answer tests and comparison tests
 * 
 * @author Joey Dodds
 */
public class CTests {

	/**
	 * Each string will be a single import file in each of the restulting C
	 * files
	 */
	private String[] imports;

	private ST header = Test.stGroup.getInstanceOf("header");
	private ST main = Test.stGroup.getInstanceOf("run_tests");
	private ST makefile = Test.stGroup.getInstanceOf("Makefile");

	private Test test;
	private File outDir;

	/**
	 * Writes files to execute C tests. This includes a KAT file for each
	 * algorithm and for each library that is being tested Writes some static
	 * files common to all tests, as well as a makefile and a header file
	 * 
	 * @param outDir
	 *            top level tests directory. This method outputs files to
	 *            directory/C_tests
	 * @param inDir
	 *            directory to read C_tests file from
	 * @param test
	 *            test cases to generate code for
	 */
	public void writeTestFiles(File outDir, File inDir, Test test) {
		this.outDir = new File(outDir.getPath() + File.separator + "C_tests");
		this.outDir.mkdirs();
		new File(this.outDir.getPath() + File.separator + "output").mkdirs();
		this.test = test;
		File testFile = new File(inDir.getPath() + File.separator + "C_tests");

		Scanner scan = null;
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

		while (scan.hasNext()) {
			makeTests(scan.nextLine());
		}
	}

	/**
	 * @param algorithm
	 *            the name of the algorithm to write KATs for
	 * @param libs
	 *            List of names of libraries to generate tests for. One test
	 *            file will be generated for each library
	 */
	private void makeCKAT(String algorithm, List<String> libs) {
		KAT kat = test.getKAT(algorithm);
		for (String lib : libs) {
			ST impSt = Test.stGroup.getInstanceOf("Ctests");
			for (String imp : imports) {
				impSt.add("imports", imp);
			}
			addKATs(algorithm, lib, kat, impSt);

			String filename = algorithm + "_" + lib + "_" + "KAT.c";
			makefile.add("cFiles", filename);
			Test.writeSTToOutDir(filename, outDir.getPath(), impSt);
		}
	}

	/**
	 * Creates tests for a single algorithm. There will be one test file
	 * generated for each library that is being tested for that algorithm
	 * 
	 * @param testString
	 *            A single line of the C_tests file
	 */
	private void makeTests(String testString) {
		Scanner scan = new Scanner(testString);
		String primitive = scan.next();
		LinkedList<String> libs = new LinkedList<String>();
		while (scan.hasNext()) {
			libs.add(scan.next());
		}

		if (test.getKAT(primitive) != null) {
			makeCKAT(primitive, libs);
		}

		if (test.getTestFile(primitive) != null) {
			makeCompare(primitive, libs);
		}
		scan.close();

		writeFiles();
	}

	/**
	 * Creates a single C file that gathers pointers to each implementation into
	 * an array and then calls each on the test files specified in {@link #test}
	 * 
	 * @param algorithm
	 *            algorithm being tested
	 * @param libs
	 *            list of libraries being tested
	 */
	private void makeCompare(String algorithm, LinkedList<String> libs) {
		ST compareST = Test.stGroup.getInstanceOf("Ctests");

		for (String imp : imports) {
			compareST.add("imports", imp);
		}

		for (String testName : test.getTestFile(algorithm)) {
			ST oneCompare = Test.stGroup.getInstanceOf("CCompare");

			oneCompare.add("algorithm", algorithm);
			oneCompare.add("testname", testName);
			oneCompare.add("funcct", libs.size());
			for (String lib : libs) {
				oneCompare.add("libs", lib);
			}

			compareST.add("tests", oneCompare.render());

			main.add("testNames", algorithm + "_" + testName);
			header.add("testNames", algorithm + "_" + testName);
		}
		
		String filename = algorithm + "_compare.c";
		makefile.add("cFiles", filename);
		Test.writeSTToOutDir(filename, outDir.getPath(), compareST);

	}

	/**
	 * Writes the files that need to be written with every test. These include
	 * {@link #copyStaticFiles(String)}, header files, toplevel file and
	 * Makefile
	 */
	private void writeFiles() {
		copyStaticFiles();
		Test.writeSTToOutDir("tests.h", outDir.getPath(), header);
		Test.writeSTToOutDir("run_tests.c", outDir.getPath(), main);
		Test.writeSTToOutDir("Makefile", outDir.getPath(), makefile);
	}

	/**
	 * Copies common C files, headers and readme into {@link #outDir}
	 */
	private void copyStaticFiles() {
		copyFiles("tmp" + File.separator + "Ccommon_test.c", outDir.getPath()
				+ File.separator + "Ccommon_test.c");
		copyFiles("tmp" + File.separator + "Ccommon_test.h", outDir.getPath()
				+ File.separator + "Ccommon_test.h");
		copyFiles("tmp" + File.separator + "README.md", outDir.getPath()
				+ File.separator + "README.md");

	}

	/**
	 * @param src
	 *            Location of source file to copy
	 * @param dest
	 *            Location of destination file to copy to, overwriting if needed
	 */
	private static void copyFiles(String src, String dest) {
		Path source = Paths.get(src);
		Path destination = Paths.get(dest);
		try {
			Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING);
		} catch (IOException e) {
			System.err.println("unable to copy file from "
					+ source.toAbsolutePath() + " to "
					+ destination.toAbsolutePath());
			e.printStackTrace();
		}
	}

	/**
	 * @param bytes
	 * @return C string initializer for unsigned byte array to create an
	 *         equivalent array to the input
	 */
	private static String biteArrayToCString(byte[] bytes) {
		StringBuilder sb = new StringBuilder("{ ");
		for (byte byt : bytes) {
			sb.append(byt & 0xFF); // convert to unsigned
			sb.append(" ,");
		}
		sb.deleteCharAt(sb.length() - 1); // there'll be an extra comma
		sb.append("}");
		return sb.toString();
	}

	/**
	 * @param ki
	 * @return string representing the input. Tries to match the way the input
	 *         was given in the KAT file
	 */
	// TODO output C hex string if hex was given as input
	private String getKiString(KATInput ki) {
		if (ki.inputAs.equals("string") && ki.bytes.length < 500) {
			return ("\"" + new String(ki.bytes) + "\"");
		} else {
			return biteArrayToCString(ki.bytes);
		}
	}

	/**
	 * @param ki
	 *            input
	 * @return A string representing "processed" input. This string is ready to
	 *         be assigned to a C variable If there is a repeat, this fills in
	 *         the template appropriately
	 */
	private String processInput(KATInput ki) {

		if (ki.repeat <= 1) {
			return getKiString(ki);
		}

		ST repeat = Test.stGroup.getInstanceOf("repeat");
		repeat.add("repeats", ki.repeat);
		repeat.add("string", getKiString(ki));
		repeat.add("stringlength", ki.bytes.length);
		return repeat.render();
	}

	/**
	 * Populates a test file with KATs for a simple implementation and primitive
	 * 
	 * @param primitive
	 * @param implementation
	 * @param kat
	 * @param testST
	 *            Template that needs it's "tests" attribute added
	 */
	private void addKATs(String primitive, String implementation, KAT kat,
			ST testST) {
		int ct = 0;
		for (Entry<KATInput, String> kv : kat.getEntries()) {
			ST oneKAT = Test.stGroup.getInstanceOf("CKAT");
			if (kv.getKey().comment != null) {
				oneKAT.add("comment", kv.getKey().comment);
			}
			if (kv.getKey().repeat > 1) {
				oneKAT.add("malloc", "yup!");
			}
			oneKAT.add("inputsize", kv.getKey().bytes.length
					* kv.getKey().repeat);
			oneKAT.add("outputsize", kv.getValue().length() / 2);

			if (kv.getKey().repeat <= 1) {
				oneKAT.add("input", processInput(kv.getKey()));
			} else {
				oneKAT.add("input", "malloc(sizeof(char) * "
						+ kv.getKey().bytes.length * kv.getKey().repeat + ")");
				oneKAT.add("repeat", processInput(kv.getKey()));
			}

			oneKAT.add("answer", CTests.hexToCUChar(new String(kv.getValue())));

			String funcname = primitive + "_" + implementation;
			String testname = funcname + "_KAT_" + ct++;

			oneKAT.add("testname", testname);
			oneKAT.add("func", funcname);

			testST.add("tests", oneKAT.render());

			main.add("testNames", testname);
			header.add("testNames", testname);

		}
	}

	/**
	 * @param st
	 *            Hex string with no spaces
	 * @return String containing a C array initializer to create an unsigned
	 *         char equal to the value given by st
	 */
	public static String hexToCUChar(String st) {
		StringBuilder sb = new StringBuilder();
		if (st.length() % 2 != 0) {
			throw new RuntimeErrorException(null, "String " + st
					+ " is not a valid length for a digest");
		}
		for (int i = 0; i < st.length(); i = i + 2) {
			sb.append("0x");
			sb.append(st.charAt(i));
			sb.append(st.charAt(i + 1));
			if (i + 2 < st.length()) {
				sb.append(", ");
			}
			if (i != 0 && (i + 2) % 16 == 0) {
				sb.append("\n");
			}
		}
		return sb.toString();
	}

}
