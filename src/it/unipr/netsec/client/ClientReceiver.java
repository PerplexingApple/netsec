package it.unipr.netsec.client;

import it.unipr.netsec.crypto.DesCrypt;
import it.unipr.netsec.server.SocketUtil;
import it.unipr.netsec.view.ClientView;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ClientReceiver implements Runnable {
	private static final Logger LOGGER = Logger.getLogger( ClientReceiver.class.getName() );
	
	ClientView view;
	Client client;
	
	//===================================
	// Constructor
	//===================================
	public ClientReceiver(Client client, ClientView view) {
		super();
		
		LOGGER.log(Level.INFO, "Starting up ViewController... ");
		
		this.client = client;
		this.view = view;	
	}	

	//===================================
	// Methods
	//===================================
	@Override
	public void run() {
		
		while (true) {
			try {
			
				LOGGER.log(Level.INFO, "Client is ready to receive new messages... ");
				
				byte[] recovered = DesCrypt.decrypt( SocketUtil.receive( client.getInSecure() ), client.getAliceDesKey() );
			
				System.out.printf(new String(recovered) );
				
				LOGGER.log(Level.INFO, "View is writing a message... ");
				view.updateText(new String(recovered) );				
				
				if( "QUIT".equals(new String(recovered)) ){
					client.close();
					return;
				}
			} catch (Exception e) {
				LOGGER.log(Level.SEVERE, e.toString());
			}
		}
	}

}
