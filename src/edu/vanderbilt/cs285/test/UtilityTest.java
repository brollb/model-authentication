package edu.vanderbilt.cs285.test;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
	public static void setUpOnce() {
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
	/*
	 * Tests that E( session request || username || HMAC(MSG, HK), SU )
	 */
	public void testSessionRequest() throws UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException {

		byte[] sessionRequest = CryptoUtilities.sessionRequest(psk_, null,
				username_, serverKeys_.getPublic());
		asymCipher_.init(Cipher.DECRYPT_MODE, serverKeys_.getPrivate());
		byte[] plainBytes = asymCipher_.doFinal(sessionRequest);
		byte[] requestBytes = new byte[CryptoUtilities.SESSION_REQUEST
				.getBytes().length];
		byte[] userBytes = new byte[username_.getBytes().length];
		byte[] hmacBytes = new byte[plainBytes.length
				- (CryptoUtilities.SESSION_REQUEST.getBytes().length + username_
						.getBytes().length)];

		System.arraycopy(plainBytes, 0, requestBytes, 0, requestBytes.length);
		assertEquals(CryptoUtilities.SESSION_REQUEST, new String(requestBytes,
				CryptoUtilities.PLAINTEXT_ENCODING));

		System.arraycopy(plainBytes, requestBytes.length, userBytes, 0,
				userBytes.length);
		assertEquals(username_, new String(userBytes,
				CryptoUtilities.PLAINTEXT_ENCODING));

		System.arraycopy(plainBytes, requestBytes.length + userBytes.length,
				hmacBytes, 0, hmacBytes.length);
		String keyString = psk_.toString();
		assertEquals(CryptoUtilities.hmacDigest(CryptoUtilities.SESSION_REQUEST
				+ username_, keyString), new String(hmacBytes,
				CryptoUtilities.PLAINTEXT_ENCODING));

	}

	@Test
	/*
	 * Tests E( E( SK0 || TL, PU) , SR) is returned by getNewSessionResponse()
	 */
	public void testGetNewSessionResponse() throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException {
		byte[] sessionResponse = CryptoUtilities.getNewSessionResponse(
				phoneKeys_.getPublic(), serverKeys_.getPrivate(), 10);

		asymCipher_.init(Cipher.DECRYPT_MODE, serverKeys_.getPublic());
		byte[] halfway = asymCipher_.doFinal(sessionResponse);

		asymCipher_.init(Cipher.DECRYPT_MODE, phoneKeys_.getPrivate());
		byte[] response = asymCipher_.doFinal(halfway);

		byte[] tlBytes = new byte[4];// one int worth of bytes
		System.arraycopy(response, response.length - 4, tlBytes, 0, 4);
		assertEquals(10, ByteBuffer.wrap(tlBytes).getInt());

	}

}
