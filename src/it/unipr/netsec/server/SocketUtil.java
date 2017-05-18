package it.unipr.netsec.server;

import it.unipr.netsec.util.ByteFunc;
import it.unipr.netsec.util.Message;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SocketUtil {
	
	private static final Logger LOGGER = Logger.getLogger( SocketUtil.class.getName() );

	private SocketUtil() {
	    throw new IllegalAccessError("Utility class");
	  }
	
	//===================================
	// Methods
	//===================================
	/**
	 * Create a socket with the supplied port number
	 * @param port
	 * @return
	 * @throws IOException
	 */
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
	
	/**
	 * Read the command line input and save it into a byte Array
	 * @param reader
	 * @param out
	 * @return
	 */
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


}
