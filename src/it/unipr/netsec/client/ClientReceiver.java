package it.unipr.netsec.client;

import it.unipr.netsec.crypto.DesCrypt;
import it.unipr.netsec.util.ByteFunc;
import it.unipr.netsec.util.Message;
import it.unipr.netsec.util.SocketUtil;
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
	/**
	 * Wrapper for receiving an encrypted message
	 * @return
	 * @throws Exception
	 */
	public byte[] receive() throws Exception{
		byte[] crypted = SocketUtil.receive( client.getInSecure() );
		byte[] recovered = DesCrypt.decrypt( crypted, client.getAliceDesKey() );
		
		System.out.printf(new String(recovered) );
		
		return recovered;
	}
	
	/**
	 * Wrapper for sending a message that needs to be encrypted
	 * @param message
	 * @throws Exception 
	 */
	public void send(Message message) throws Exception {
		Message cipherMessage = new Message( DesCrypt.encrypt( message.getText(), client.getAliceDesKey()) );
		LOGGER.log(Level.INFO, "Alice has encrypted DES ECB ciphertext: " + ByteFunc.bytesToHexString( cipherMessage.getText() ));
		
		LOGGER.log(Level.INFO, "Sending ciphertext ...");
		SocketUtil.send(cipherMessage, client.getOutSecure() );
	}
	
	@Override
	public void run() {
		
		while (true) {
			try {
			
				LOGGER.log(Level.INFO, "Client is ready to receive new messages... ");
				
				byte[] recovered = receive();
				
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
