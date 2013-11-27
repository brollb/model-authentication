package edu.vanderbilt.cs285.test;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import edu.vanderbilt.cs285.utilities.CryptoUtilities;

public class UtilityTest {

	private Key psk_;
	private KeyPair phoneKeys_;
	private KeyPair serverKeys_;
	private Cipher symCipher_;
	private Cipher asymCipher_;
	private final String username_ = "TESTUSER";
	private IvParameterSpec iv_;
	
	@BeforeClass
	public static void setUpOnce(){
		CryptoUtilities.allowEncryption();
	}
	
	@Before
	public void setUp() throws Exception {
		KeyGenerator kg = KeyGenerator.getInstance(CryptoUtilities.SYMMETRIC_KEY_ALGORITHM);
		kg.init(CryptoUtilities.SYM_KEY_SIZE);
		psk_ = kg.generateKey();
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoUtilities.ASYMMETRIC_KEY_ALGORITHM);
	    keyGen.initialize(1024);
	    phoneKeys_ = keyGen.generateKeyPair();
	    serverKeys_ = keyGen.generateKeyPair();
	    
	    symCipher_ = CryptoUtilities.getSymmetricCipher();
	    
	    asymCipher_ = CryptoUtilities.getAsymmetricCipher();
	    
	    SecureRandom random = new SecureRandom();
		byte[] ivBytes = new byte[CryptoUtilities.IV_LENGTH];
		random.nextBytes(ivBytes);
		iv_ = new IvParameterSpec(ivBytes);
	    
	}

	@After
	public void tearDown() throws Exception {
	}
	
	@Test
	public void testSessionRequest() throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException{
		
		byte[] sessionRequest = CryptoUtilities.sessionRequest(psk_,iv_, username_, phoneKeys_.getPrivate());
		
		byte[] request = new byte[CryptoUtilities.REQUEST_LENGTH_1];
		System.arraycopy(sessionRequest, 0, request, 0, CryptoUtilities.REQUEST_LENGTH_1);
		
		byte[] saltedUser = new byte[CryptoUtilities.REQUEST_LENGTH_2];
		System.arraycopy(sessionRequest, CryptoUtilities.REQUEST_LENGTH_1, saltedUser, 0, CryptoUtilities.REQUEST_LENGTH_2);
		
		symCipher_.init(Cipher.DECRYPT_MODE, psk_,iv_);
		byte[] requestPlain = symCipher_.doFinal(request);
		assertEquals(CryptoUtilities.SESSION_REQUEST, new String(requestPlain,CryptoUtilities.PLAINTEXT_ENCODING));
		
		asymCipher_.init(Cipher.DECRYPT_MODE, phoneKeys_.getPublic());
		byte[] userAndSaltPlain = asymCipher_.doFinal(saltedUser);
		byte[] userPlain = new byte[username_.getBytes().length];
		System.arraycopy(userAndSaltPlain, 0, userPlain, 0, userPlain.length);
		assertEquals(username_, new String(userPlain, CryptoUtilities.PLAINTEXT_ENCODING));
	}

}
