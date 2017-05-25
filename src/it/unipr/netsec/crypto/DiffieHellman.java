package it.unipr.netsec.crypto;

import it.unipr.netsec.client.Client;
import it.unipr.netsec.util.Message;
import it.unipr.netsec.util.SocketUtil;

import java.io.BufferedInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class DiffieHellman {

	//==================================================================
	//Constants
	//==================================================================
	private static final Logger LOGGER = Logger.getLogger( DiffieHellman.class.getName() );

	// The 1024 bit Diffie-Hellman modulus values
	private static final byte[] skip1024ModulusBytes = {
		(byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
		(byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
		(byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
		(byte)0x91, (byte)0x07, (byte)0x36, (byte)0x6B,
		(byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D,
		(byte)0x45, (byte)0x1D, (byte)0x0F, (byte)0x7C,
		(byte)0x88, (byte)0xB3, (byte)0x1C, (byte)0x7C,
		(byte)0x5B, (byte)0x2D, (byte)0x8E, (byte)0xF6,
		(byte)0xF3, (byte)0xC9, (byte)0x23, (byte)0xC0,
		(byte)0x43, (byte)0xF0, (byte)0xA5, (byte)0x5B,
		(byte)0x18, (byte)0x8D, (byte)0x8E, (byte)0xBB,
		(byte)0x55, (byte)0x8C, (byte)0xB8, (byte)0x5D,
		(byte)0x38, (byte)0xD3, (byte)0x34, (byte)0xFD,
		(byte)0x7C, (byte)0x17, (byte)0x57, (byte)0x43,
		(byte)0xA3, (byte)0x1D, (byte)0x18, (byte)0x6C,
		(byte)0xDE, (byte)0x33, (byte)0x21, (byte)0x2C,
		(byte)0xB5, (byte)0x2A, (byte)0xFF, (byte)0x3C,
		(byte)0xE1, (byte)0xB1, (byte)0x29, (byte)0x40,
		(byte)0x18, (byte)0x11, (byte)0x8D, (byte)0x7C,
		(byte)0x84, (byte)0xA7, (byte)0x0A, (byte)0x72,
		(byte)0xD6, (byte)0x86, (byte)0xC4, (byte)0x03,
		(byte)0x19, (byte)0xC8, (byte)0x07, (byte)0x29,
		(byte)0x7A, (byte)0xCA, (byte)0x95, (byte)0x0C,
		(byte)0xD9, (byte)0x96, (byte)0x9F, (byte)0xAB,
		(byte)0xD0, (byte)0x0A, (byte)0x50, (byte)0x9B,
		(byte)0x02, (byte)0x46, (byte)0xD3, (byte)0x08,
		(byte)0x3D, (byte)0x66, (byte)0xA4, (byte)0x5D,
		(byte)0x41, (byte)0x9F, (byte)0x9C, (byte)0x7C,
		(byte)0xBD, (byte)0x89, (byte)0x4B, (byte)0x22,
		(byte)0x19, (byte)0x26, (byte)0xBA, (byte)0xAB,
		(byte)0xA2, (byte)0x5E, (byte)0xC3, (byte)0x55,
		(byte)0xE9, (byte)0x2F, (byte)0x78, (byte)0xC7
	};

	// The SKIP 1024 bit modulus
	private static final BigInteger skip1024Modulus = new BigInteger(1, skip1024ModulusBytes);

	// The base used with the SKIP 1024 bit modulus
	private static final BigInteger skip1024Base = BigInteger.valueOf(2);

	//==================================================================
	//Variables
	//==================================================================
	KeyAgreement aliceKeyAgree;
	KeyAgreement bobKeyAgree;
	PublicKey alicePubKey;
	PublicKey bobPubKey;
	X509EncodedKeySpec x509KeySpec;


	//==================================================================
	//Getters and Setters
	//==================================================================
	public PublicKey getAlicePubKey() {
		return alicePubKey;
	}

	public PublicKey getBobPubKey() {
		return bobPubKey;
	}

	/**
	 * Getter for Alice KeyAgreement
	 * @return
	 */
	public KeyAgreement getAliceKeyAgree() {
		return aliceKeyAgree;
	}
	
	/**
	 * Getter for Bob KeyAgreement
	 * @return
	 */
	public KeyAgreement getBobKeyAgree() {
		return bobKeyAgree;
	}

	public X509EncodedKeySpec getX509KeySpec() {
		return x509KeySpec;
	}

	//==================================================================
	//Methods
	//==================================================================
	/**
	 * Generates DH Parameters. Modes: default parameters or new parameters
	 * @param mode
	 * @return DHParameterSpec containing the parameters that are a prime p, a base g, 
	 * and optionally the length in bits of the private value, l.
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidParameterSpecException
	 */
	public static DHParameterSpec generateDhParamenters(String mode) throws Exception{
		DHParameterSpec dhSkipParamSpec;

		if ("GENERATE_DH_PARAMS".equals(mode)) {
			// Create new DH parameters
			LOGGER.log(Level.INFO, "Creating Diffie-Hellman parameters (takes VERY long) ...");

			AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
			paramGen.init(512);

			AlgorithmParameters param = paramGen.generateParameters();
			dhSkipParamSpec = param.getParameterSpec(DHParameterSpec.class);
		} 
		else {
			// use pre-generated, default DH parameters
			LOGGER.log(Level.INFO, "Using SKIP Diffie-Hellman parameters");
			dhSkipParamSpec = new DHParameterSpec(skip1024Modulus, skip1024Base);
		} 
		return dhSkipParamSpec;
	}

	/**
	 * Generates a Key Pair from a set of DH Parameters using a Key Generator set to the DH algorithm
	 * @param dhSkipParamSpec
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static KeyPair generateDhKeyPair(DHParameterSpec dhSkipParamSpec) throws Exception {
		LOGGER.log(Level.INFO, "ALICE: Generating DH keypair ...");
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
		keyPairGen.initialize(dhSkipParamSpec);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		LOGGER.log(Level.INFO, "KeyPair generated");
		
		return keyPair;
	}
	/**
	 * Compute a Key Agreement from the Key PAir
	 * @param key_pair
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyAgreement computeDhSecret(KeyPair keyPair) throws Exception {
		KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
		keyAgree.init(keyPair.getPrivate());
		LOGGER.log(Level.INFO, "KeyAgreement initialized");
		
		return keyAgree;
	}

	/**
	 * Generating alicePubKeyEnc for sending to Bob
	 * @param mode specifies whether or not to use default parameters
	 * @return alicePubKeyEnc
	 * @throws Exception
	 */
	public byte[] initializeAlice(String mode) throws Exception {
		DHParameterSpec dhSkipParamSpec = generateDhParamenters(mode);

		//Alice creates her own DH key pair, using the DH parameters from above
		LOGGER.log(Level.INFO, "ALICE: generating DH key pair ...");
		KeyPair aliceKpair = generateDhKeyPair(dhSkipParamSpec);

		// Alice creates and initializes her DH KeyAgreement object
		LOGGER.log(Level.INFO, "ALICE: DH KeyAgreement Initialization ...");
		this.aliceKeyAgree = computeDhSecret(aliceKpair);

		// Alice encodes her public key, and sends it over to Bob.
		byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();
		LOGGER.log(Level.INFO, "AlicePubKey is ready for sending ...");
		return alicePubKeyEnc;
	}

	/**
	 * Generating bobPubKeyEnc for sending to Alice.
	 * Bob instantiates a DH public key from the encoded key material(Alice's public key in encoded format).
	 * @param alicePubKeyEnc
	 * @return bobPubKeyEnc
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	public byte[] initilizeBobFromAlice(byte[] alicePubKeyEnc) throws Exception{

		KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
		LOGGER.log(Level.INFO, "BOB: generating x509 key ...");
		this.x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);

		LOGGER.log(Level.INFO, "BOB: generating alicePubKey ...");
		this.alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

		// Bob gets the DH parameters associated with Alice's public key.
		DHParameterSpec dhParamSpec = ((DHPublicKey)alicePubKey).getParams();

		// Bob creates his own DH key pair
		LOGGER.log(Level.INFO, "BOB: Generate DH key pair ...");
		KeyPair bobKpair = generateDhKeyPair(dhParamSpec);

		// Bob creates and initializes his DH KeyAgreement object
		LOGGER.log(Level.INFO, "BOB: Initialization ...");
		this.bobKeyAgree = KeyAgreement.getInstance("DH");
		this.bobKeyAgree.init(bobKpair.getPrivate());

		// Bob encodes his public key for sending over to Alice.
		byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();
		LOGGER.log(Level.INFO, "BobPubKey is ready for sending ...");
		return bobPubKeyEnc;		
	}

	/**
	 * Uses bobPubKeyEnc to save a bobPubKey for future use
	 * Instantiates a DH public key from Bob's encoded key material.
	 * Sets last phase flag to true because only 2 entities are exchanging
	 * @param bobPubKeyEnc
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws NoSuchAlgorithmException
	 */
	public void lastPhaseAlice(byte[] bobPubKeyEnc) throws Exception{

		KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
		this.x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
		this.bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
		LOGGER.log(Level.INFO, "ALICE: Execute PHASE last ...");
		this.aliceKeyAgree.doPhase(bobPubKey, true);
	}

	/**
	 * Uses alicePubKeyEnc to save a alicePubKey for future use
	 * Sets last phase flag to true
	 * @param alicePubKey
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 */
	public void lastPhaseBob(PublicKey alicePubKey) throws Exception{
		
		LOGGER.log(Level.INFO, "BOB: Execute PHASE last ...");
		this.bobKeyAgree.doPhase(alicePubKey, true);
	}

	/**
	 * Encapsulates everything necessary for exchanging in a Diffie Hellman key exchange
	 * @return DiffieHellman object containing all data
	 * @throws Exception
	 */
	public static DiffieHellman createUnsecureDHExchangeFromAlice(String host, int port) throws Exception{
	
		LOGGER.log(Level.INFO, "Creating unsecure connection... ");
		Socket unsecureSocket = SocketUtil.connectToServerSocket(host, port);
	
		ObjectOutputStream outStream = SocketUtil.createOut(unsecureSocket);	
		ObjectInputStream inStream = SocketUtil.createIn(unsecureSocket);	
	
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

	/**
	 * Encapsulates everything necessary for exchanging in a Diffie Hellman key exchange
	 * @return DiffieHellman object containing all data
	 * @throws Exception
	 */
	public static DiffieHellman createUnsecureDHExchangeFromBob(Socket unsecureSocket) throws Exception{
	
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

}
