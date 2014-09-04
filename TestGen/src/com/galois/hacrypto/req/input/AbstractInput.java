package com.galois.hacrypto.req.input;

/**
 * Contains information common to all inputs, currently just the name.
 * 
 * @author dmz
 */
public abstract class AbstractInput implements Input {
	protected final String name;
	
	public AbstractInput(final String name) {
		this.name = name;
	}
	
	public String getName() { 
		return name;
	}
}
