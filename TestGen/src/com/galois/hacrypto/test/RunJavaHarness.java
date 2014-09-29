package com.galois.hacrypto.test;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Date;
import java.util.Map.Entry;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.galois.hacrypto.req.Req;

/**
 * Runs all tests listed in a specified file, reading .req files from and
 * generating the corresponding .rsp files for those tests at a specified
 * directory root.
 * 
 * @author dmz
 */
public class RunJavaHarness {
	/**
	 * A File object representing the input directory. 
	 */
	private final File inputDir;
	
	/**
	 * A File object representing the output directory.
	 */
	private final File outputDir;
	
	/**
	 * A File object representing the test spec directory.
	 */
	private final File testDir;

	/**
	 * The name of the file to use as the test list.
	 */
	private final String testList;
	
	/**
	 * The suffix to use for input files.
	 */
	private final String reqSuffix;
	
	/**
	 * @param testDirName
	 *            The directory that holds the test definitions such as tests,
	 *            C_tests, and KAT files
	 * @param inputDirName
	 *            The directory that contains all the request files.
	 * @param outputDirName 
	 *            The directory that contains all the response files.
	 */
	public RunJavaHarness(String testDirName, String inputDirName, String outputDirName,
			String testList, String reqSuffix) {
		inputDir = new File(inputDirName);
		outputDir = new File(outputDirName);
		testDir = new File(testDirName);
		this.testList = testList;
		this.reqSuffix = reqSuffix;
	}
	
	/**
	 * Runs all the tests that are present in the harness_tests file that also have
	 * corresponding test definitions and request files, generating the appropriate
	 * response files.
	 */
	public void run() {
		File rspdir = new File(outputDir.getPath() + File.separator + "rsp");
		rspdir.mkdirs();
		File testFile = new File(testDir.getAbsolutePath() + File.separator + testList);
		Scanner testReader = null;
		try {
			testReader = new Scanner(testFile);
		} catch (FileNotFoundException e) {
			System.err.println("File " + testFile.getAbsolutePath()
					+ " not found");
			e.printStackTrace();
		}
		while (testReader.hasNext()) {
			readTestLine(testReader.nextLine());
		}
	}

	private void createFile(String fileName) {
		Req r;
		String algName = fileName.substring(0, fileName.indexOf('/'));
		String testName = fileName.substring(fileName.indexOf('/') + 1);
		File testSpec = new File(testDir.getAbsolutePath() + File.separator 
				+ algName + File.separator + testName);
		if (!testSpec.exists()) {
			// no matching test spec, print an output line and return
			System.err.println("No test spec found for " + fileName + ", skipping test.");
			return;
		}
		File req = new File(inputDir.getPath() + File.separator + algName 
				+ File.separator + reqSuffix + File.separator
				+ testName + "." + reqSuffix);
		if (!req.exists()) {
			// no matching tests, print an output line and exit
			System.err.println("No request file " + fileName + " found, skipping test.");
			return;
		}
		File rspDir = new File(outputDir.getPath() + File.separator + algName 
				+ File.separator + "resp");
		rspDir.mkdirs();
		try {
			r = new Req(req.getAbsolutePath(), testSpec.getAbsolutePath());
			Entry<String, String> reqrsp = r.createReqRsp();
			Util.writeStringToOutDir(testName + ".rsp", rspDir.getPath(), reqrsp.getValue());
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Skipping test.");
		}
	}

	/**
	 * Handles a line of a harnesses file.
	 * 
	 * @param line An entire line of a harnesses file.
	 */
	private void readTestLine(String line) {
		Scanner lineReader = new Scanner(line);
		while (lineReader.hasNext()) {
			final String s = lineReader.next();
			System.err.println("Running test " + s);
			createFile(s);
		}
		lineReader.close();
	}
	
	public static void main(String args[]) {
		String testSpecDir = "test_defs";
		String inputDir = "output";
		String outputDir = "outputH";
		String testList = "harness_tests";
		String reqSuffix = "req";
		
		if (args.length >= 3) {
			// assume the first argument is the test spec directory
			// the second is the input directory
			// the third is the output directory (usually the same as the second)
			// the fourth is the list of tests to run (default "harness_tests") 
			// the fifth is the suffix/dir name for test specs (default "req")
			testSpecDir = args[0];
			inputDir = args[1];
			outputDir = args[2];
			if (args.length > 3) {
				testList = args[3];
			}
			if (args.length > 4) {
				reqSuffix = args[4];
			}
		} 
		
		System.err.println("Testing BouncyCastle Version " + (new BouncyCastleProvider()).getVersion());
		System.err.println("Starting run at " + new Date());
		long startTime = System.currentTimeMillis();
		final RunJavaHarness rt = new RunJavaHarness(testSpecDir, inputDir, outputDir, testList, reqSuffix);
		rt.run();
		long finishTime = System.currentTimeMillis();
		System.err.println("Run ended at " + new Date());
		long msec = finishTime - startTime;
		long seconds = msec / 1000;
		msec = msec % 1000;
		long minutes = seconds / 60;
		seconds = seconds % 60;
		System.err.printf("Elapsed time: %d:%02d.%03d\n\n", minutes, seconds, msec);
	}
}
