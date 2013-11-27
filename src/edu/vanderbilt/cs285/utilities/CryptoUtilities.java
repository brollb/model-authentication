package edu.vanderbilt.cs285.utilities;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;

public class CryptoUtilities {

	public static final String SYMMETRIC_KEY_ALGORITHM = "AES";
	public static final String ASYMMETRIC_KEY_ALGORITHM = "RSA";
	public static final String HMAC_ALGORITHM = "HmacMD5";
	public static final String SESSION_REQUEST = "This is a session request";
	public static final String PLAINTEXT_ENCODING = "UTF8";
	public static final String SYM_CYPHER_MODE = "CBC";
	public static final String ASYM_CYPHER_MODE = "ECB";
	public static final String SYM_PADDING_TYPE = "PKCS5Padding";
	public static final String ASYM_PADDING_TYPE = "PKCS1Padding";
	public static final int SYM_KEY_SIZE = 256;
	public static final int ASYM_KEY_SIZE = 1024;
	public static final int REQUEST_LENGTH_1 = 32; //E( session request, PSK )
	public static final int REQUEST_LENGTH_2 = 128; //E( username || salt, PR )
	public static final int SALT_LENGTH = 26;
	public static final int IV_LENGTH = 16;
	
	/*
	 * returns the byte[] that represents E( session request || username || HMAC(MSG, HK), SU )
	 * that should be sent from the phone to the server every time a new session key is needed.
	 * As parameters, it takes the Symmetric Secret key, the current session key (null if the first time),
	 * the username for the client, and the server's public key to encrypt the whole thing.
	 */
	public static byte[] sessionRequest(Key psk, Key sk, String user, PublicKey su) throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		String keyString;
		if (sk == null)
			keyString = psk.toString();
		else{
			byte[] k1 = psk.getEncoded();
			byte[] k2 = sk.getEncoded();
			byte[] xor = new byte[k1.length];
			for (int i =0; i<k1.length; i++){
				xor[i] = (byte) (k1[i] ^ k2[i]);
			}
			keyString = new String(xor);
		}
		String payload = SESSION_REQUEST+user;
		payload += hmacDigest(payload, keyString);
		
		Cipher asymCipher = getAsymmetricCipher();
		asymCipher.init(Cipher.ENCRYPT_MODE, su);
		return asymCipher.doFinal(payload.getBytes());
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
	 * Convenience function used to allow the utilization of large keys for encryption. You will need to call
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
	

	/*
	 * convenience method to get symmetric key
	 */
	public static Key getSymmetricKey() throws NoSuchAlgorithmException{
		KeyGenerator kg = KeyGenerator.getInstance(SYMMETRIC_KEY_ALGORITHM);
		kg.init(SYM_KEY_SIZE);
		return kg.generateKey();
	}
	
	/*
	 * convenience method to get asymmetric key. Use bigKey=true for the server key
	 */
	public static KeyPair getKeypair(boolean bigKey) throws NoSuchAlgorithmException{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoUtilities.ASYMMETRIC_KEY_ALGORITHM);
	    if (bigKey)
	    	keyGen.initialize(CryptoUtilities.ASYM_KEY_SIZE*2);
	    else
	    	keyGen.initialize(CryptoUtilities.ASYM_KEY_SIZE);
	    return keyGen.generateKeyPair();
	}

	/*
	 * returns a byte[] that is E( E( SK0 || TL, PU) , SR)
	 */
	public static byte[] getNewSessionResponse(PublicKey pu, PrivateKey sr, int tl) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		Key newSessionKey = getSymmetricKey();
		byte[] keyBytes = newSessionKey.getEncoded();
		byte[] timesLeftBytes = ByteBuffer.allocate(4).putInt(tl).array();
		byte[] payload = new byte[keyBytes.length+timesLeftBytes.length];
		System.arraycopy(keyBytes, 0, payload, 0, keyBytes.length);
		System.arraycopy(timesLeftBytes,0,payload,keyBytes.length,timesLeftBytes.length);
		
		Cipher asymCipher = getAsymmetricCipher();
		asymCipher.init(Cipher.ENCRYPT_MODE, pu);
		byte[] halfway = asymCipher.doFinal(payload);
		
		asymCipher.init(Cipher.ENCRYPT_MODE, sr);
		return asymCipher.doFinal(halfway);
		
	}

	/*
	 * Adding a method for convenient HMAC generation
	 */
	 public static String hmacDigest(String msg, String keyString) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
		 String digest = null;
		 SecretKeySpec key = new SecretKeySpec((keyString).getBytes(PLAINTEXT_ENCODING), SYMMETRIC_KEY_ALGORITHM);
		 Mac mac = Mac.getInstance(HMAC_ALGORITHM);
		 mac.init(key);

		 byte[] bytes = mac.doFinal(msg.getBytes(PLAINTEXT_ENCODING));//May not need to convert it to UTF8 - depends what the server will use

		 StringBuffer hash = new StringBuffer();
		 for (int i = 0; i < bytes.length; i++) {
			 String hex = Integer.toHexString(0xFF & bytes[i]);
			 if (hex.length() == 1) {
				 hash.append('0');
			 }
			 hash.append(hex);
		 }
		 digest = hash.toString();

		 return digest;
	 }
	
}
