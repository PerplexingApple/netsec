package it.unipr.netsec.server;

import it.unipr.netsec.crypto.DesCrypt;
import it.unipr.netsec.crypto.DiffieHellman;
import it.unipr.netsec.util.ByteFunc;
import it.unipr.netsec.util.Message;
import it.unipr.netsec.util.SocketUtil;

import java.io.BufferedInputStream;
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
import javax.print.attribute.standard.Severity;

public class ServerThread extends Thread{

	//===================================
	// Constants
	//===================================
	private static final int SECURE_PORT_NUMBER = 1060;
	private static final Logger LOGGER = Logger.getLogger( ServerThread.class.getName() );	

	
	//===================================
	// Variables
	//===================================
	Server server;
	
	private Socket unsecureSocket;
	private Socket secureSocket;
	
	private ObjectOutputStream outSecure;
	private ObjectInputStream inSecure;
	
	private SecretKey bobDesKey;

	//===================================
	// Constructor
	//===================================
	public ServerThread(Socket unsecureSocket, Server server) {
		LOGGER.log(Level.INFO, "Receiving a socket from main...");
		
		this.unsecureSocket = unsecureSocket;
		this.server = server;
	}

	//===================================
	// Methods
	//===================================
	/**
	 * Wrapper for server use for sending messages that need to be encrypted .
	 * Accepts messages, then encrypts contained text and sends new Messages in their place
	 * @param message to be encrypted and sent
	 */
	public void send(Message message) {
		try {
			byte[] textToBeSentSecurely = message.getText();
			Message messageToBeSent = new Message(DesCrypt.encrypt( textToBeSentSecurely, bobDesKey) );
			SocketUtil.send( messageToBeSent, outSecure);
			
		} catch (Exception  e) {
			LOGGER.log(Level.SEVERE, e.toString() );
		}
	}
	
	/**
	 * Wrapper for receiving an encrypted message
	 * @return
	 * @throws Exception
	 */
	public byte[] receive() throws Exception{
		byte[] recovered = DesCrypt.decrypt( SocketUtil.receive(inSecure), bobDesKey);
		System.out.printf(new String(recovered) + "%n");
		
		return recovered;
	}
	
	/**
	 * Open secure Object Streams
	 */
	public void open(){
		try {
			this.outSecure = new ObjectOutputStream(secureSocket.getOutputStream());		
			outSecure.flush();
			LOGGER.log(Level.INFO, "Creating secure outputStream ...");
	
			this.inSecure = new ObjectInputStream(new BufferedInputStream(secureSocket.getInputStream()));
			LOGGER.log(Level.INFO, "Creating secure inputStream ...");
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, e.toString() );
		}	
	}
	
	/**
	 * Close sockets to avoid resource leaks
	 */
	public void close(){
		LOGGER.log(Level.INFO, "Client has finished his connection");
		try {
			secureSocket.close();
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, e.toString() );
		}
	}

	@Override
	public void run(){
		
		try {			

			DiffieHellman diffieBob = DiffieHellman.createUnsecureDHExchangeFromBob(unsecureSocket);		

			this.secureSocket = SocketUtil.connectToClientSocket(SECURE_PORT_NUMBER);

			//start of the DES encryption
			bobDesKey = DesCrypt.createDesKey(diffieBob.getBobKeyAgree(), diffieBob.getAlicePubKey() );

			open();	

			//===========================================================
			while (true) {

				LOGGER.log(Level.INFO, "Waiting for encrypted message ...");
				byte[] recovered = receive();
				
				server.handle(new Message(recovered));
				
				if("QUIT".equals(new String(recovered)) ){
					close();
					return;
				}
			}
			//============================================================

		} catch (Exception e) {
			LOGGER.log(Level.SEVERE, e.toString() );
		}	             

		LOGGER.log(Level.INFO, "Finished");

	}


}
