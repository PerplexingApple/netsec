package it.unipr.netsec.view;

import it.unipr.netsec.client.Client;
import it.unipr.netsec.crypto.DesCrypt;
import it.unipr.netsec.server.ServerThread;
import it.unipr.netsec.server.SocketUtil;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class ViewController implements Runnable {
	private static final Logger LOGGER = Logger.getLogger( ViewController.class.getName() );
	
	ObjectInputStream in;
	SecretKey key;
	Socket secureSocket;
	ClientView view;
	Client client;
	
	public ViewController(Client client) {
		super();
		this.client = client;
		this.key = client.getAliceDesKey();
		this.secureSocket = client.getSecureSocket();
		
		LOGGER.log(Level.INFO, "Starting up ViewController... ");
	}	

	@Override
	public void run() {
		
		while (true) {
			try {
				//LOGGER.log(Level.INFO, "Waiting for encrypted message ...");
			
				LOGGER.log(Level.INFO, "Client is ready to receive new messages... ");
				
				//recovered = DesCrypt.decrypt( SocketUtil.receive(in), key);
				byte[] recovered = SocketUtil.receive( client.getInSecure() );
			
				System.out.printf(new String(recovered) );
				
				LOGGER.log(Level.INFO, "View is writing a message... ");
				client.getView().updateText(new String(recovered) );
				
				
				if(new String(recovered)=="QUIT"){
					LOGGER.log(Level.INFO, "Client has finished his connection");

					secureSocket.close();
					return;
				}
			} catch (ClassNotFoundException	| IOException e) {
				LOGGER.log(Level.SEVERE, e.toString());
			}
		}
	}

}
