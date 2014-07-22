package com.galois.hacrypto;

import java.util.LinkedList;
import java.util.List;

import org.stringtemplate.v4.ST;
import org.stringtemplate.v4.STGroup;
import org.stringtemplate.v4.STGroupDir;
import org.stringtemplate.v4.STGroupFile;

public class CKAT {
	
	private String input;
	private String answer;
	private List<String> functions;
	private String testName;
	
	public CKAT(String input, String answer, List<String> functions, String testName) {
		super();
		this.input = input;
		this.answer = answer;
		this.functions = functions;
		this.testName = testName;
	}
	
	public String toString(){
		STGroup stGroup = new STGroupFile("tmp/CKAT.stg");
		ST st = stGroup.getInstanceOf("CKAT");
		st.add("input", input);
		st.add("answer", Test.hexToCUChar(answer));
		st.add("testname", testName);
		for(String function:functions){
			st.add("funcs", function);
		}
		st.add("inputsize", input.length());
		st.add("outputsize", answer.length()/2);
		return st.render();
	}
	
	public static void main(String args[]){
		List<String> l = new LinkedList<>();
		l.add("SHA256_VST");
		l.add("SHA256_nss");
		CKAT testCKAT = new CKAT("The quick brown fox jumps over the lazy dog",
				"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
				l, "test0");
		System.out.println(testCKAT);	
	}
	
}
