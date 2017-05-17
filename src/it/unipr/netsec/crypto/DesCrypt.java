package it.unipr.netsec.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import it.unipr.netsec.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.util.logging.Level;
import java.util.logging.Logger;

public class DesCrypt {
	
	private static final Logger LOGGER = Logger.getLogger( DesCrypt.class.getName() );
	Cipher cipher;
	String key_algo;
	SecretKey secret_key;
	
	public static SecretKey desKey(KeyAgreement keyAgree, PublicKey pubKey) throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException{		
		// The call to bobKeyAgree.generateSecret above reset the key
        // agreement object, so we call doPhase again prior to another
        // generateSecret call
        keyAgree.doPhase(pubKey, true);
        SecretKey desKey = keyAgree.generateSecret("DES");
        LOGGER.log(Level.INFO, "Return shared secret as SecretKey object ...");
        return desKey;
	}
	
	/**
	 * Encrypt plaintext through the initialized Cipher
	 * @param plaintext
	 * @return ciphertext in a byte array
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static byte[] encrypt(byte[] cleartext, SecretKey desKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{

        Cipher cipher = Cipher.getInstance( defaultAlgo() );
        cipher.init(Cipher.ENCRYPT_MODE, desKey);

        LOGGER.log(Level.INFO, "DES ECB plaintext: " + ByteFunc.bytesToHexString(cleartext));
        byte[] ciphertext = cipher.doFinal(cleartext);
        LOGGER.log(Level.INFO, "DES ECB ciphertext: " + ByteFunc.bytesToHexString(ciphertext));
        
        return ciphertext;
	}
	
	/**
	 * Decrypt ciphertext through the initialized Cipher
	 * @param ciphertext
	 * @return plaintext in a byte array
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static byte[] decrypt(byte[] ciphertext, SecretKey desKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
		Cipher aliceCipher = Cipher.getInstance( defaultAlgo() );
        aliceCipher.init(Cipher.DECRYPT_MODE, desKey);
        byte[] recovered = aliceCipher.doFinal(ciphertext);
        LOGGER.log(Level.INFO, "Alice reads cleartext: " + ByteFunc.bytesToHexString(recovered));
		return recovered;
	}
	
	
	/////
	//Getters and setters
	/////
	/**
	 * choose default padding and algorithm
	 * @return
	 */
	private static String defaultAlgo() {
		return "DES/ECB/PKCS5Padding";
	}
	
	/**
	 * create a 16 bytes long key array
	 * @param hexKey
	 * @return
	 */
	public byte[] hexkeyToBytes(String hexKey) {
		return ByteFunc.hexStringToByteArray(hexKey);
	}

	/**
	 * transform into a 16 bytes long initialization vector
	 * @param hexIV
	 * @return
	 */
	public byte[] hexIvToBytes(String hexIV) {
		return ByteFunc.hexStringToByteArray(hexIV);
	}

}
