package it.unipr.netsec.client;

import it.unipr.netsec.crypto.DesCrypt;
import it.unipr.netsec.crypto.DiffieHellman;
import it.unipr.netsec.server.SocketUtil;
import it.unipr.netsec.util.ByteFunc;
import it.unipr.netsec.util.Message;
import it.unipr.netsec.view.ClientView;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
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
	ClientView view;
	IncomingTrafficListener controller;
	BufferedReader reader;
	
	DiffieHellman diffieAlice;
	SecretKey aliceDesKey;	
	
	ObjectOutputStream outSecure;
	ObjectInputStream inSecure;	
	Socket secureSocket;
	
	
	//===================================
	// Constructor
	//===================================
	private Client() throws Exception {
		this.reader = new BufferedReader(new InputStreamReader(System.in));	
	
		this.diffieAlice = createUnsecureDHExchangeFromAlice();		

		this.secureSocket = connectToServerSocket(HOST_NAME, SECURE_SOCKET_PORT);		    	

		this.aliceDesKey = DesCrypt.desKey(diffieAlice.getAliceKeyAgree(), diffieAlice.getBobPubKey());

		this.outSecure = createOut(secureSocket);

		this.inSecure = createIn(secureSocket);
		
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
	 * 
	 * @param host
	 * @param port
	 * @return
	 * @throws IOException
	 */
	public static Socket connectToServerSocket(String host, int port) throws IOException{
		Socket clientSocket = null;
		clientSocket = new Socket(host, port);

		LOGGER.log(Level.INFO, "Connecting to: " + host + " " + port);
		return clientSocket;
	}
	
	/**
	 * Encapsulates everything necessary for exchanging in a Diffie Hellman key exchange
	 * @return DiffieHellman object containing all data
	 * @throws Exception
	 */
	public static DiffieHellman createUnsecureDHExchangeFromAlice() throws Exception{
	
		LOGGER.log(Level.INFO, "Creating unsecure connection... ");
		Socket unsecureSocket = connectToServerSocket(HOST_NAME, UNSECURE_SOCKET_PORT);
	
		ObjectOutputStream outStream = createOut(unsecureSocket);	
		ObjectInputStream inStream = createIn(unsecureSocket);	
	
		String mode = "USE_SKIP_DH_PARAMS";
		DiffieHellman diffieAlice = new DiffieHellman();
		byte[] alicePubKeyEncoded = diffieAlice.initializeAlice(mode);
		LOGGER.log(Level.INFO, "Sending AlicePubKey ...");
		SocketUtil.send(new Message(alicePubKeyEncoded), outStream);
	
		byte[] bobPubKeyEncoded = SocketUtil.receive(inStream);
		diffieAlice.lastPhaseAlice(bobPubKeyEncoded);
		LOGGER.log(Level.INFO, "Alice has finished DH exchange");
	
		//Closing socket after use to prevent resource leakage
		unsecureSocket.close();
		LOGGER.log(Level.INFO, "Alice has closed an unsecure connection ...");
	
		return diffieAlice;
	}
	
	private static ObjectOutputStream createOut(Socket socket) throws IOException{
		ObjectOutputStream out = new ObjectOutputStream(new BufferedOutputStream(socket.getOutputStream()));
		out.flush();
		LOGGER.log(Level.INFO, "Created outputStream and flushed to send the header...");
		return out;
	}
	
	private static ObjectInputStream createIn(Socket socket) throws IOException{
		ObjectInputStream in = new ObjectInputStream(new BufferedInputStream(socket.getInputStream()));
		LOGGER.log(Level.INFO, "Created inputStream ...");
		return in;
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
		
		this.controller = new IncomingTrafficListener(this, view);

		view.show();
		controller.run();
			
		while(true){
			try {
				//get the message
				byte[] newTextInput = SocketUtil.getInputIntoArray(reader, System.out);
				Message cipherMessage = new Message( DesCrypt.encrypt( newTextInput, aliceDesKey) );
				LOGGER.log(Level.INFO, "Bob has encrypted DES ECB ciphertext: " + ByteFunc.bytesToHexString( cipherMessage.getText() ));
				
				if (new String(newTextInput).equalsIgnoreCase("QUIT")) {
					LOGGER.log(Level.INFO, "Closing connection with Client ...");
					
					SocketUtil.send(cipherMessage, outSecure);	
					secureSocket.close();
					
					return;
				} else {
					LOGGER.log(Level.INFO, "Sending ciphertext ...");
					SocketUtil.send(cipherMessage, outSecure);

				}
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, e.toString() );
				return;
			} catch (InvalidKeyException e) {
				LOGGER.log(Level.SEVERE, e.toString() );
			} catch (IllegalBlockSizeException e) {
				LOGGER.log(Level.SEVERE, e.toString() );
			} catch (BadPaddingException e) {
				LOGGER.log(Level.SEVERE, e.toString() );
			} catch (NoSuchAlgorithmException e) {
				LOGGER.log(Level.SEVERE, e.toString() );
			} catch (NoSuchPaddingException e) {
				LOGGER.log(Level.SEVERE, e.toString() );;
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
