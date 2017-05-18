package it.unipr.netsec.server;

import it.unipr.netsec.util.Message;

import java.io.IOException;
import java.net.Socket;
import java.util.logging.*;

public class Server implements Runnable{
	private static final int UNSECURE_PORT_NUMBER = 1051;
	private static final int SECURE_PORT_NUMBER = 1060;
	private static final Logger LOGGER = Logger.getLogger( Server.class.getName() );
	
	private static  ServerThread[] clients = new ServerThread[50];
	private static int clientCount = 0;

	private Server() {

	}

	private synchronized void addThread(Socket socket){  
		if (clientCount < clients.length){  
			System.out.println("Client accepted: " + socket);
			clients[clientCount] = new ServerThread(socket, this); 
			clients[clientCount].start();  
			clientCount++; 
		}
		else{
			LOGGER.log(Level.INFO, "Client refused: maximum " + clients.length + " reached.");
		}			
	}
	
	public void handle(Message message){  
		for(int i = 0; i<clientCount; i++){
			clients[i].send(message);
		}
	}
	
	@Override
	public void run() {
		while (true)
		{	
			//BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));			
			//int socketPort = SocketUtil.getPort(reader, System.out, "Insert the port number for Unsecure connection.");
			LOGGER.log(Level.INFO, "Creating a new socket ...");	
			Socket unsecureSocket;
			try {
				unsecureSocket = SocketUtil.connectToClientSocket(UNSECURE_PORT_NUMBER);

				LOGGER.log(Level.INFO, "Creating a thread for a new client ...");
				addThread(unsecureSocket);
				
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, e.toString() );
			}

		}
	}
	
	

	//=====================================
	//MAIN
	//=====================================
	public static void main(String[] args) throws Exception{        	    
		
		new Server().run();
	}

	
}

