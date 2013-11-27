package edu.vanderbilt.cs285.test;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
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
		psk_ = CryptoUtilities.getSymmetricKey();
	    phoneKeys_ = CryptoUtilities.getKeypair(false);
	    serverKeys_ = CryptoUtilities.getKeypair(true);
	    
	    symCipher_ = CryptoUtilities.getSymmetricCipher();
	    
	    asymCipher_ = CryptoUtilities.getAsymmetricCipher();
	    
	    iv_ = CryptoUtilities.getNewIV();
	    
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
	
	@Test
	public void testGetNewSessionResponse() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
		byte[] sessionResponse = CryptoUtilities.getNewSessionResponse(phoneKeys_.getPublic(), serverKeys_.getPrivate(), 10);
		
		asymCipher_.init(Cipher.DECRYPT_MODE, serverKeys_.getPublic());
		byte[] halfway = asymCipher_.doFinal(sessionResponse);
		
		asymCipher_.init(Cipher.DECRYPT_MODE, phoneKeys_.getPrivate());
		byte[] response = asymCipher_.doFinal(halfway);
		
		byte[] tlBytes = new byte[4];//one int worth of bytes
		System.arraycopy(response, response.length-4, tlBytes, 0, 4);
		assertEquals(10, ByteBuffer.wrap(tlBytes).getInt());
		
	}

}
