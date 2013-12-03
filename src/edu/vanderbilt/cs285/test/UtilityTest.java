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
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import edu.vanderbilt.cs285.utilities.CryptoUtilities;

public class UtilityTest {

	private SecretKey psk_;
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
		byte[] decryptedBytes = CryptoUtilities.decryptData(sessionRequest, serverKeys_.getPrivate(), null);
		String[] parts = new String(decryptedBytes, CryptoUtilities.PLAINTEXT_ENCODING).split("/");
		assertEquals(CryptoUtilities.SESSION_REQUEST, parts[0]);
		assertEquals(username_,parts[1]);
		String keyString = psk_.toString();
		assertEquals(CryptoUtilities.hmacDigest(CryptoUtilities.SESSION_REQUEST+"/"+username_, keyString), parts[2]);
	}

	@Test
	/*
	 * Tests E( E( SK0 || TL, PU) , SR) is returned by getNewSessionResponse()
	 */
	public void testGetNewSessionResponse() throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException {
		byte[] sessionResponse = CryptoUtilities.getNewSessionResponse(
				phoneKeys_.getPublic(), psk_, 10);//erverKeys_.getPrivate(), 10);

		asymCipher_.init(Cipher.DECRYPT_MODE, serverKeys_.getPublic());
		byte[] halfway = asymCipher_.doFinal(sessionResponse);

		asymCipher_.init(Cipher.DECRYPT_MODE, phoneKeys_.getPrivate());
		byte[] response = asymCipher_.doFinal(halfway);

		byte[] tlBytes = new byte[4];// one int worth of bytes
		System.arraycopy(response, response.length - 4, tlBytes, 0, 4);
		assertEquals(10, ByteBuffer.wrap(tlBytes).getInt());

	}

	@Test
	/*
	 * Tests encryption and decryption of data
	 */
	public void testEncryptAndDecryptData() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException{
		String start = "Some starting plaintext to be encrypted";
		SecretKey sk = CryptoUtilities.getSymmetricKey();
		byte[] encrypted = CryptoUtilities.encryptData(start.getBytes(CryptoUtilities.PLAINTEXT_ENCODING), sk, iv_);
		byte[] decrypted = CryptoUtilities.decryptData(encrypted, sk, iv_);
		assertEquals(start, new String(decrypted,CryptoUtilities.PLAINTEXT_ENCODING));
		
		KeyPair kp = CryptoUtilities.getKeypair(false);
		byte[] encrypted2 = CryptoUtilities.encryptData(start.getBytes(CryptoUtilities.PLAINTEXT_ENCODING), kp.getPrivate(), null);
		byte[] decrypted2 = CryptoUtilities.decryptData(encrypted2, kp.getPublic(), null);
		assertEquals(start, new String(decrypted2, CryptoUtilities.PLAINTEXT_ENCODING));
	}
	
	@Test
	/*
	 * Test the reporting of confidence scores
	 * Should be like: E ( IV, SU ) || E( RCS || TS1, SK ) || HMAC(MSG, HK)
	 */
	public void testReportConfidenceScores() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException{
		String confidScores = "1,2,3,4,5,6,8,9,71,2,3,4,5,6,8,9,71,2,3,4,5,6,8,9,71,2,3,4,5,6,8,9,7";
		String timeStamp = ""+System.currentTimeMillis()/1000;//in seconds
		byte[] payload = (confidScores+"/"+timeStamp).getBytes();
		SecretKey sk = CryptoUtilities.getSymmetricKey();
		byte[] report = CryptoUtilities.reportConfidenceScores(iv_,serverKeys_.getPublic(),confidScores, timeStamp, sk,  psk_);
		byte[] ivBytes = new byte[CryptoUtilities.IV_ENCRYPTED_LENGTH];
		byte[] hmacBytes = new byte[CryptoUtilities.HMAC_LENGTH];
		byte[] scoreAndTimestampBytes = new byte[report.length - ivBytes.length - hmacBytes.length];
		
		System.arraycopy(report, 0, ivBytes, 0, ivBytes.length);
		System.arraycopy(report, ivBytes.length, scoreAndTimestampBytes, 0, scoreAndTimestampBytes.length);
		System.arraycopy(report, report.length-hmacBytes.length, hmacBytes, 0, hmacBytes.length);
		
		IvParameterSpec theIV = new IvParameterSpec(CryptoUtilities.decryptData(ivBytes, serverKeys_.getPrivate(), null));
		String mainBody = new String(CryptoUtilities.decryptData(scoreAndTimestampBytes, sk, theIV));
		String[] splitBody = mainBody.split("/");
		assertEquals(confidScores,splitBody[0]);
		assertEquals(timeStamp, splitBody[1]);
		assertEquals(CryptoUtilities.hmacDigest(payload, CryptoUtilities.getHK(psk_, sk)), new String(hmacBytes));
	}
}
