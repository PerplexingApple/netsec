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

public class IncomingTrafficListener implements Runnable {
	private static final Logger LOGGER = Logger.getLogger( IncomingTrafficListener.class.getName() );
	
	ClientView view;
	Client client;
	
	public IncomingTrafficListener(Client client, ClientView view) {
		super();
		
		LOGGER.log(Level.INFO, "Starting up ViewController... ");
		
		this.client = client;
		this.view = view;	
	}	

	@Override
	public void run() {
		
		while (true) {
			try {
			
				LOGGER.log(Level.INFO, "Client is ready to receive new messages... ");
				
				byte[] recovered = DesCrypt.decrypt( SocketUtil.receive( client.getInSecure() ), client.getAliceDesKey() );
			
				System.out.printf(new String(recovered) );
				
				LOGGER.log(Level.INFO, "View is writing a message... ");
				view.updateText(new String(recovered) );				
				
				if(new String(recovered)=="QUIT"){
					client.close();
				}
			} catch (ClassNotFoundException	| IOException | InvalidKeyException | IllegalBlockSizeException |
					BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
				LOGGER.log(Level.SEVERE, e.toString());
			}
		}
	}

}
