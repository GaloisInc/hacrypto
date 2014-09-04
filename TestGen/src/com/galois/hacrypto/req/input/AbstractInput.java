package com.galois.hacrypto.req.input;

/**
 * Contains information common to all inputs, currently just the name.
 * 
 * @author dmz
 */
public abstract class AbstractInput implements Input {
	protected final String name;
	private final int showInOutput;
	
	public AbstractInput(final String name) {
		this(name, YES);
	}
	
	public AbstractInput(final String name, final int showInOutput) {
		this.name = name;
		this.showInOutput = showInOutput;
	}
	public String getName() { 
		return name;
	}
	
	public int showInOutput() {
		return showInOutput;
	}
}
