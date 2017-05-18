package it.unipr.netsec.server;

import it.unipr.netsec.crypto.DesCrypt;
import it.unipr.netsec.util.ByteFunc;
import it.unipr.netsec.util.Message;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SocketUtil {
	
	private static final Logger LOGGER = Logger.getLogger( SocketUtil.class.getName() );

	
	public static Socket connectToClientSocket(int port) throws IOException{

		ServerSocket serverSocket = new ServerSocket(port);
		try{
			LOGGER.log( Level.INFO, "Waiting for client on port " + serverSocket.getLocalPort() + "...");
			Socket socket = serverSocket.accept();
			LOGGER.log( Level.INFO, "Just connected to " + socket.getRemoteSocketAddress());
			return socket;

		}finally{
			serverSocket.close();
		}
	}
	
	public static int getPort(BufferedReader reader, PrintStream out, String message) {
		out.println(message);
		do {
			try {
				Integer answer = Integer.parseInt(reader.readLine());
				if (answer > 0) {
					return answer;
				}
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, e.toString());
			}
			out.printf("Port number not valid. Try again.%n");
		} while (true);
	}

	public static String getHost(BufferedReader reader, PrintStream out) {
		do {
			try {
				out.println("Insert the host.");
				return reader.readLine();
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, e.toString());
			}
			out.printf("Hostname not valid. Try again.%n");
		} while (true);
	}
	
	public static byte[] getInputIntoArray(BufferedReader reader, PrintStream out) {
		do {
			try {
				out.println("Accepting a message... ");
				return reader.readLine().getBytes();
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, e.toString());
			}
			out.printf("Input not valid. Try again.%n");
		} while (true);
	}
	
	/**
	 * Sends a message in a Message format
	 * @param text
	 * @param out
	 * @throws IOException
	 */
	public static void send(Message message, ObjectOutputStream out) throws IOException{	    	
		Message currMessage = message;
		out.writeObject(currMessage);
		LOGGER.log(Level.INFO, "sending message: " + ByteFunc.bytesToHexString(currMessage.getText() ) );
		out.flush();
	}

	/**
	 * Receive a Byte Array contained in a Message object
	 * @param inStream
	 * @return text in a byte array
	 * @throws ClassNotFoundException
	 * @throws IOException
	 */
	public static byte[] receive(ObjectInputStream inStream) throws Exception{
		Message currMessage = (Message) inStream.readObject();
		LOGGER.log(Level.INFO, "receiving message: " + ByteFunc.bytesToHexString(currMessage.getText() ) );
		return currMessage.getText();
	}
	
	public void receiveCrypted(Socket secureSocket, ObjectInputStream inSecure, SecretKey bobDesKey){
		byte[] recovered;
		try {
			recovered = DesCrypt.decrypt( receive(inSecure), bobDesKey);
		
			System.out.printf(new String(recovered) + "%n");
			if( "QUIT".equals(new String(recovered)) ){
				LOGGER.log(Level.INFO, "Finished");
	
				secureSocket.close();
				return;
			}
		} catch (Exception e) {
			LOGGER.log(Level.SEVERE, e.toString() );
		}
	}


}
