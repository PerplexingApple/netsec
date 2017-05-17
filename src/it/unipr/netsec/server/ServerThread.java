package it.unipr.netsec.server;

import it.unipr.netsec.crypto.DesCrypt;
import it.unipr.netsec.crypto.DiffieHellman;
import it.unipr.netsec.util.ByteFunc;
import it.unipr.netsec.util.Message;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.print.attribute.standard.Severity;

public class ServerThread extends Thread{

	private static final int SECURE_PORT_NUMBER = 1060;
	private static final Logger LOGGER = Logger.getLogger( ServerThread.class.getName() );	

	Server server;
	
	private Socket unsecureSocket;
	private Socket secureSocket;
	
	private ObjectOutputStream outSecure;
	private ObjectInputStream inSecure;
	private BufferedReader reader;

	public ServerThread(Socket unsecureSocket, Server server) {
		LOGGER.log(Level.INFO, "Receiving a socket from main...");
		
		this.unsecureSocket = unsecureSocket;
		this.server = server;
		this.reader = new BufferedReader(new InputStreamReader(System.in));
	}

	/**
	 * Encapsulates everything necessary for exchanging in a Diffie Hellman key exchange
	 * @return DiffieHellman object containing all data
	 * @throws Exception
	 */
	private static DiffieHellman createUnsecureDHExchangeFromBob(Socket unsecureSocket) throws Exception{

		ObjectOutputStream outStream = new ObjectOutputStream(unsecureSocket.getOutputStream());
		outStream.flush();
		LOGGER.log(Level.INFO, "Created unsecure outputStream ...");
		ObjectInputStream inStream = new ObjectInputStream(new BufferedInputStream(unsecureSocket.getInputStream()));
		LOGGER.log(Level.INFO, "Created unsecure inputStream ...");	                

		DiffieHellman diffieBob = new DiffieHellman();

		LOGGER.log(Level.INFO, "receiving AlicePubKeyEnc ...");
		byte[] alicePubKeyEnc = SocketUtil.receive(inStream);	    		    
		byte[] bobPubKeyEnc = diffieBob.initilizeBobFromAlice(alicePubKeyEnc);

		SocketUtil.send(new Message(bobPubKeyEnc), outStream);

		diffieBob.lastPhaseBob( diffieBob.getAlicePubKey() );
		LOGGER.log(Level.INFO, "Bob has finished DH exchange");	

		//Closing socket after use to prevent resource leakage
		unsecureSocket.close();
		LOGGER.log(Level.INFO, "Bob has closed unsecure connection ...");

		return diffieBob;
	}
	
	/**
	 * Wrapper for server use
	 * @param message
	 */
	public void send(Message message) {
		try {
			SocketUtil.send(message, outSecure);
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, e.toString() );
		}
	}
	
	
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
	
	public void close(){
		LOGGER.log(Level.INFO, "Client has finished his connection");
		try {
			secureSocket.close();
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, e.toString() );
		}
	}

	public void run(){
		
		try {			

			DiffieHellman diffieBob = createUnsecureDHExchangeFromBob(unsecureSocket);		

			this.secureSocket = SocketUtil.connectToClientSocket(SECURE_PORT_NUMBER);

			//start of the DES encryption
			SecretKey bobDesKey = DesCrypt.desKey(diffieBob.getBobKeyAgree(), diffieBob.getAlicePubKey() );

			open();	

			//===========================================================
			while (true) {

				LOGGER.log(Level.INFO, "Waiting for encrypted message ...");
				byte[] recovered = DesCrypt.decrypt( SocketUtil.receive(inSecure), bobDesKey);
				System.out.printf(new String(recovered) + "%n");
				
				server.handle(new Message(recovered));
				
				if(new String(recovered)=="QUIT"){
					LOGGER.log(Level.INFO, "Client has finished his connection");

					secureSocket.close();
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
