package edu.vanderbilt.cs285.utilities;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
	public static final int SYM_KEY_SIZE = 128;
	public static final int ASYM_KEY_SIZE = 1024;
	public static final int IV_LENGTH = 16;
	public static final int IV_ENCRYPTED_LENGTH = 256;
	public static final int HMAC_LENGTH = 32;

	/*
	 * returns the byte[] that represents E( session request || username ||
	 * HMAC(MSG, HK), SU ) that should be sent from the phone to the server
	 * every time a new session key is needed. As parameters, it takes the
	 * Symmetric Secret key, the current session key (null if the first time),
	 * the username for the client, and the server's public key to encrypt the
	 * whole thing.
	 */
	public static byte[] sessionRequest(Key psk, Key sk, String user,
			PublicKey su) throws InvalidKeyException,
			UnsupportedEncodingException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		String keyString;
		if (sk == null)
			keyString = psk.toString();
		else 
			keyString = getHK(psk,sk);
		String payload = SESSION_REQUEST +"/"+ user;
		payload += "/" + hmacDigest(payload, keyString);

		Cipher asymCipher = getAsymmetricCipher();
		asymCipher.init(Cipher.ENCRYPT_MODE, su);
		return asymCipher.doFinal(payload.getBytes());
	}
	
	/*
	 * Little helper function to combine psk and sk for an hk
	 */
	public static String getHK(Key psk,Key sk){
		byte[] k1 = psk.getEncoded();
		byte[] k2 = sk.getEncoded();
		byte[] xor = new byte[k1.length];
		for (int i = 0; i < k1.length; i++) {
			xor[i] = (byte) (k1[i] ^ k2[i]);
		}
		return new String(xor);
	}

	/*
	 * returns a new IV, to be used with symmetric key encription since we are
	 * using CBC
	 */
	public static IvParameterSpec getNewIV() {
		SecureRandom random = new SecureRandom();
		byte[] ivBytes = new byte[CryptoUtilities.IV_LENGTH];
		random.nextBytes(ivBytes);
		return new IvParameterSpec(ivBytes);
	}

	/*
	 * convenience method to return a symmetric cipher using the algorithms and
	 * modes we've specified in our documentation.
	 */
	public static Cipher getSymmetricCipher() throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		return Cipher.getInstance(SYMMETRIC_KEY_ALGORITHM + "/"
				+ SYM_CYPHER_MODE + "/" + SYM_PADDING_TYPE);
	}

	/*
	 * convenience method to return an asymmetric cipher using the algorithms
	 * and modes we've specified in our documentation.
	 */
	public static Cipher getAsymmetricCipher() throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		return Cipher.getInstance(ASYMMETRIC_KEY_ALGORITHM + "/"
				+ ASYM_CYPHER_MODE + "/" + ASYM_PADDING_TYPE);
	}

	/*
	 * Convenience function used to allow the utilization of large keys for
	 * encryption. You will need to call this at the beginning of any "main"
	 * function. If you fail to, you will get:
	 * java.security.InvalidKeyException: Invalid Key Length
	 */
	public static void allowEncryption() {
		try {
			java.lang.reflect.Field field = Class.forName(
					"javax.crypto.JceSecurity")
					.getDeclaredField("isRestricted");
			field.setAccessible(true);
			field.set(null, java.lang.Boolean.FALSE);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	/*
	 * convenience method to get symmetric key
	 */
	public static SecretKey getSymmetricKey() throws NoSuchAlgorithmException {
		KeyGenerator kg = KeyGenerator.getInstance(SYMMETRIC_KEY_ALGORITHM);
		kg.init(SYM_KEY_SIZE);
		return kg.generateKey();
	}

	/*
	 * convenience method to get asymmetric key. Use bigKey=true for the server
	 * key
	 */
	public static KeyPair getKeypair(boolean bigKey)
			throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator
				.getInstance(CryptoUtilities.ASYMMETRIC_KEY_ALGORITHM);
		if (bigKey)
			keyGen.initialize(CryptoUtilities.ASYM_KEY_SIZE * 2);
		else
			keyGen.initialize(CryptoUtilities.ASYM_KEY_SIZE);
		return keyGen.generateKeyPair();
	}

	/*
	 * returns a byte[] that is E( E( SK0 || TL, PU) , SK)
	 */
	public static byte[] getNewSessionResponse(PublicKey pu, SecretKey sk,
			int tl) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Key newSessionKey = getSymmetricKey();
		byte[] keyBytes = newSessionKey.getEncoded();
		byte[] timesLeftBytes = ByteBuffer.allocate(4).putInt(tl).array();
		byte[] payload = new byte[keyBytes.length + timesLeftBytes.length];
		System.arraycopy(keyBytes, 0, payload, 0, keyBytes.length);
		System.arraycopy(timesLeftBytes, 0, payload, keyBytes.length,
				timesLeftBytes.length);

		
		
		Cipher asymCipher = getAsymmetricCipher();
		asymCipher.init(Cipher.ENCRYPT_MODE, pu);
		byte[] halfway = asymCipher.doFinal(payload);

		Cipher symCipher = getSymmetricCipher();
		symCipher.init(Cipher.ENCRYPT_MODE, sk);
		return symCipher.doFinal(halfway);

	}

	/*
	 * Adding a method for convenient HMAC generation
	 */
	public static String hmacDigest(String msg, String keyString) 
			throws InvalidKeyException, UnsupportedEncodingException, 
			NoSuchAlgorithmException {

		return hmacDigest(msg.getBytes(PLAINTEXT_ENCODING), keyString);
}

	public static String hmacDigest(byte[] msg, String keyString)
			throws UnsupportedEncodingException, NoSuchAlgorithmException,
			InvalidKeyException {
		String digest = null;
		SecretKeySpec key = new SecretKeySpec(
				(keyString).getBytes(PLAINTEXT_ENCODING),
				SYMMETRIC_KEY_ALGORITHM);
		Mac mac = Mac.getInstance(HMAC_ALGORITHM);
		mac.init(key);

		byte[] bytes = mac.doFinal(msg);
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

	/*
	 * Utility function for easy encription of data, given a key.
	 * To get said key, try CryptoUtilities.getAsymmetricKey() or CryptoUtilities.getSymmetricKey()
	 * The iv is only for symmetric encryption, null otherwise
	 */
	public static byte[] encryptData(byte[] data, Key key, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
		return encryptOrDecryptData(data, key, iv, Cipher.ENCRYPT_MODE);
	}
	
	/*
	 * helper function for encryption or decryption. Should you encryptData() or decryptData() 
	 */
	private static byte[] encryptOrDecryptData(byte[] data, Key key,IvParameterSpec iv, int mode) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
		
		//asymmetric encryption
		if (key instanceof PublicKey || key instanceof PrivateKey){
			Cipher asymCipher = getAsymmetricCipher();
			asymCipher.init(mode, key);
			return asymCipher.doFinal(data);
		}
		//else if symmetic encryption
		else if (key instanceof SecretKey){
			Cipher symCipher = getSymmetricCipher();
			symCipher.init(mode, key, iv);
			return symCipher.doFinal(data);
		}
		else{
			throw new InvalidKeyException("the passed key was neither a symmetric nor asymmetric key");
		}
	}
	
	/*
	 * Utility function for easy decryption of data, given a key.
	 * the iv is for symmetric decryption. Null otherwise
	 */
	public static byte[] decryptData(byte[] data, Key key,IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
		return encryptOrDecryptData(data, key, iv, Cipher.DECRYPT_MODE);
	}
	
	/*
	 * function for creating the packet to send the recent confidence scores
	 * achieves the packet that represents: E ( IV, SU ) || E( RCS || TS1, SK ) || HMAC(MSG, HK)
	 * in this case, MSG == RCS || TS1
	 */
	public static byte[] reportConfidenceScores(IvParameterSpec iv, PublicKey su, String rcs, String ts, SecretKey sk,  SecretKey psk) throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
		byte[] ivBytes = iv.getIV();
		byte[] main = (rcs+"/"+ts).getBytes();
		String hk = getHK(psk, sk);
		
		
		byte[] ivEncBytes = encryptData(ivBytes, su, null);
		byte[] mainEncBytes = encryptData(main, sk, iv);
		byte[] hmac = hmacDigest(main, hk).getBytes();
		
		byte[] result = new byte[ivEncBytes.length+mainEncBytes.length+hmac.length];
		System.arraycopy(ivEncBytes, 0, result, 0, ivEncBytes.length);
		System.arraycopy(mainEncBytes, 0, result, ivEncBytes.length, mainEncBytes.length);
		System.arraycopy(hmac, 0, result, result.length-hmac.length, hmac.length);
		
		return result;
	}
		
	/*
	 * Converting from key to string and vice-versa methods
	 */
	public static String createKeyString(Key key){
	    BASE64Encoder encoder = new BASE64Encoder();

	    return encoder.encode(key.getEncoded());
	}
	
	public static Key createKeyFromString(String keyString, String algo) throws IOException{
	    BASE64Decoder decoder = new BASE64Decoder();
	    byte[] encodedKey = decoder.decodeBuffer(keyString);

	    return new SecretKeySpec(encodedKey,0,encodedKey.length, algo);     

	}
	
}
