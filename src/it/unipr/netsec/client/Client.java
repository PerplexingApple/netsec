package it.unipr.netsec.client;

import it.unipr.netsec.crypto.DesCrypt;
import it.unipr.netsec.crypto.DiffieHellman;
import it.unipr.netsec.util.ByteFunc;
import it.unipr.netsec.util.Message;
import it.unipr.netsec.util.SocketUtil;
import it.unipr.netsec.view.ClientView;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Client implements Runnable{

	private static final int UNSECURE_SOCKET_PORT = 1051;
	private static final String HOST_NAME = "localhost";
	private static final int SECURE_SOCKET_PORT = 1060;
	
	private static final Logger LOGGER = Logger.getLogger( Client.class.getName() );

	//===================================
	// Variables
	//===================================
	private ClientView view;
	private ClientReceiver controller;
	private BufferedReader reader;
	
	private DiffieHellman diffieAlice;
	private SecretKey aliceDesKey;	
	
	private ObjectOutputStream outSecure;
	private ObjectInputStream inSecure;	
	private Socket secureSocket;
	
	
	//===================================
	// Constructor
	//===================================
	private Client() throws Exception {
		this.reader = new BufferedReader(new InputStreamReader(System.in));	
	
		this.diffieAlice = DiffieHellman.createUnsecureDHExchangeFromAlice(HOST_NAME, UNSECURE_SOCKET_PORT);		

		this.secureSocket = SocketUtil.connectToServerSocket(HOST_NAME, SECURE_SOCKET_PORT);		    	

		this.aliceDesKey = DesCrypt.createDesKey(diffieAlice.getAliceKeyAgree(), diffieAlice.getBobPubKey());

		this.outSecure = SocketUtil.createOut(secureSocket);

		this.inSecure = SocketUtil.createIn(secureSocket);
		
	}
	
	//===================================
	// Getters and setters
	//===================================
	public SecretKey getAliceDesKey() {
		return aliceDesKey;
	}

	public ObjectInputStream getInSecure() {
		return inSecure;
	}
	
	public ObjectOutputStream getOutSecure() {
		return outSecure;
	}

	public Socket getSecureSocket() {
		return secureSocket;
	}

	public ClientView getView() {
		return view;
	}

	//===================================
	// Methods
	//===================================
	/**
	 * Wrapper for sending encrypted messages
	 * @param message
	 * @throws IOException
	 */
	public void send(Message message) throws IOException {
		LOGGER.log(Level.INFO, "Sending ciphertext ...");
		SocketUtil.send(message, outSecure);
	}
	
	public void close(){
		LOGGER.log(Level.INFO, "Client has finished his connection");
		try {
			secureSocket.close();
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, e.toString() );
		}
	}
	
	@Override
	public void run() {
		
		this.view = new ClientView(outSecure, aliceDesKey );
		
		this.controller = new ClientReceiver(this, view);

		view.show();
		controller.run();
			
		while(true){
			try {
				//get the message
				byte[] newTextInput = SocketUtil.getInputIntoArray(reader, System.out);
				Message cipherMessage = new Message( DesCrypt.encrypt( newTextInput, aliceDesKey) );
				LOGGER.log(Level.INFO, "Bob has encrypted DES ECB ciphertext: " + ByteFunc.bytesToHexString( cipherMessage.getText() ));
				
				if ("QUIT".equals(new String(newTextInput)) ) {
					LOGGER.log(Level.INFO, "Closing connection from Client ...");
					
					SocketUtil.send(cipherMessage, outSecure);	
					secureSocket.close();					
					return;
				} else {
					send(cipherMessage);
				}
			} catch (Exception e) {
				LOGGER.log(Level.SEVERE, e.toString() );
				return;
			}
		}
		//==============================================================
		
	}

	//===============================
	//MAIN
	//===============================
	public static void main(String[] args) throws Exception {

		new Client().run();
	}


	
}
