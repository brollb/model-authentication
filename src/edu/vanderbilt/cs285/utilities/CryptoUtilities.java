package edu.vanderbilt.cs285.utilities;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;

public class CryptoUtilities {

	public static final String SYMMETRIC_KEY_ALGORITHM = "AES";
	public static final String ASYMMETRIC_KEY_ALGORITHM = "RSA";
	public static final String SESSION_REQUEST = "This is a session request";
	public static final String PLAINTEXT_ENCODING = "UTF8";
	public static final String SYM_CYPHER_MODE = "CBC";
	public static final String ASYM_CYPHER_MODE = "ECB";
	public static final String SYM_PADDING_TYPE = "PKCS5Padding";
	public static final String ASYM_PADDING_TYPE = "PKCS1Padding";
	public static final int SYM_KEY_SIZE = 256;
	public static final int REQUEST_LENGTH_1 = 32; //E( session request, PSK )
	public static final int REQUEST_LENGTH_2 = 128; //E( username || salt, PR )
	public static final int SALT_LENGTH = 26;
	public static final int IV_LENGTH = 16;
	
	/*
	 * returns the byte[] that represents E( session request, PSK ) || E( username || salt, PR )
	 * that should be sent from the phone to the server every time a new session key is needed.
	 * As parameters, it takes the Symmetric Secret key, an IV (get a new one with getNewIV())
	 * the username for the client, and the client's private key to sign the request.
	 */
	public static byte[] sessionRequest(Key key, IvParameterSpec iv, String user, PrivateKey pk) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
		
		Cipher symCipher = Cipher.getInstance(SYMMETRIC_KEY_ALGORITHM+"/"+SYM_CYPHER_MODE+"/"+SYM_PADDING_TYPE);
		symCipher.init(Cipher.ENCRYPT_MODE, key, iv);
		byte[] requestPlain = SESSION_REQUEST.getBytes(PLAINTEXT_ENCODING);
		byte[] requestBytes = symCipher.doFinal(requestPlain);		
		
		Cipher asymCipher = Cipher.getInstance(ASYMMETRIC_KEY_ALGORITHM+"/"+ASYM_CYPHER_MODE+"/"+ASYM_PADDING_TYPE);
		asymCipher.init(Cipher.ENCRYPT_MODE, pk);
		SecureRandom random = new SecureRandom();
		String salt = new BigInteger(130, random).toString(32);
		String saltedUser = user+salt;
		byte[] saltedUserPlainBytes = saltedUser.getBytes(CryptoUtilities.PLAINTEXT_ENCODING);
		byte[] saltedUserBytes = asymCipher.doFinal(saltedUserPlainBytes);
		
		byte[] result = new byte[requestBytes.length + saltedUserBytes.length];;
		System.arraycopy(requestBytes, 0, result, 0, requestBytes.length);
		System.arraycopy(saltedUserBytes, 0,result,requestBytes.length,saltedUserBytes.length);
		
		return result;
	}
	
	/*
	 * returns a new IV, to be used with symmetric key encription since we are using CBC
	 */
	public static IvParameterSpec getNewIV(){
		SecureRandom random = new SecureRandom();
		byte[] ivBytes = new byte[CryptoUtilities.IV_LENGTH];
		random.nextBytes(ivBytes);
		return new IvParameterSpec(ivBytes);
	}
	
	/*
	 * convenience method to return a symmetric cipher using the algorithms and modes we've 
	 * specified in our documentation.
	 */
	public static Cipher getSymmetricCipher() throws NoSuchAlgorithmException, NoSuchPaddingException{
		return Cipher.getInstance(SYMMETRIC_KEY_ALGORITHM + "/" + SYM_CYPHER_MODE + "/" + SYM_PADDING_TYPE);
	}
	
	/*
	 * convenience method to return an asymmetric cipher using the algorithms and modes we've 
	 * specified in our documentation. 
	 */
	public static Cipher getAsymmetricCipher() throws NoSuchAlgorithmException, NoSuchPaddingException{
		return Cipher.getInstance(ASYMMETRIC_KEY_ALGORITHM + "/" + ASYM_CYPHER_MODE + "/" + ASYM_PADDING_TYPE);
	}
	
	/*
	 * Convenience function used to allow the utilization of large keys for encryiption. You will need to call
	 * this at the beginning of any "main" function. If you fail to, you will get:
	 * java.security.InvalidKeyException: Invalid Key Length
	 * 
	 */
	public static void allowEncryption(){
		try {
	        java.lang.reflect.Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
	        field.setAccessible(true);
	        field.set(null, java.lang.Boolean.FALSE);
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
	}
	
}
