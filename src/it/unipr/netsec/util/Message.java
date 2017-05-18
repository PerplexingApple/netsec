package it.unipr.netsec.util;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;


public class Message implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private byte[] text;
	private int command;

	//===================================
	// Constructors
	//===================================
	/**
	 * Saves a string as a byte array
	 * @param text is a String of text
	 */
	public Message(String text) {		
		plaintextToBytes( text );			
	}
	/**
	 * Alternative constructor for easier messages
	 * @param text is a byte array of text
	 */
	public Message(byte[] text) {		
		this.text = text;			
	}
	
	
	//===================================
	// Getters and setters
	//===================================
	public byte[] getText() {
		return this.text;
	}
	
	public void setText(byte[] text) {
		this.text = text;;
	}

	public void plaintextToBytes(String text) {
		this.text = text.getBytes();
	}

	public int getCommand() {
		return command;
	}

	public void setCommand(int command) {
		this.command = command;
	}

	
}
