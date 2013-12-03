package edu.vanderbilt.cs285.utilities;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class Server {
	/*
	 * Server will need:
	 *       - Public/Private Key Pair
	 *       - Storing:
	 *            - User - Public Key - PSK (HMAC checking) - Session Key - Expiration Date
	 *            - Confidence Scores
	 *            
	 * 
	 */
	private static final int CONFIDENCE_BITS = 4;
	private static final int TIMESTAMP_BITS = 4;
	private static final int TIMES_LEFT = 10;

	private static final int SERVER_PORT = 8000;
	private static final String LOG_FILE_PATH = "";
	private static Map<String, userData> users = new HashMap<String, userData>();
	private static KeyPair keyPair;
	private static SecureRandom random = new SecureRandom();

	public static void main(String args[]) throws Exception{
		/*
		 * I added this simply for testing.
		 * 
		 * To test, go to localhost:8000/test.
		 */
		initialize();
	}

	public static void initialize() throws Exception {
		System.setProperty("java.net.preferIPv4Stack", "true");
		HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getByName("0.0.0.0"), SERVER_PORT), 0);
		System.out.println();
		System.out.println("Listening on: " + server.getAddress().toString().substring(1));
		System.out.println("\n");
		server.createContext("/", new MyHandler());
		server.setExecutor(null); // creates a default executor
		CryptoUtilities.allowEncryption();//allows the server to use heavy encryption algorithms and key sizes
		keyPair = CryptoUtilities.getKeypair(true);
		server.start();

		/* Key k = CryptoUtilities.getSymmetricKey();
	        IvParameterSpec iv = CryptoUtilities.getNewIV();
	        byte[] b = CryptoUtilities.encryptData((new String("testtesttesttest")).getBytes(), k, iv);
	        System.out.println("E length: "+b.length);
	        byte[] h = CryptoUtilities.decryptData(b, k, iv);
	        System.out.println("D length: "+h.length);

	        KeyPair k = CryptoUtilities.getKeypair(false);
	        IvParameterSpec iv = CryptoUtilities.getNewIV();
	        byte[] b = CryptoUtilities.encryptData(iv.getIV(), k.getPublic(), iv);
	        System.out.println("E length: "+b.length);*/
	}

	static class MyHandler implements HttpHandler {
		public void handle(HttpExchange t) throws IOException {

			//Only respond to POST requests
			/*if(!t.getRequestMethod().equals("POST")) { 
	            	String res = "Method not allowed: " + t.getRequestMethod();
	            	t.sendResponseHeaders(405, res.length());
	            	OutputStream os = t.getResponseBody();
		            os.write(res.getBytes());
		            os.close();
	            	return;
	            }*/

			System.out.println(t.getRemoteAddress().getAddress().toString().substring(1));
			

			String userID = null;
			String request = null;
			String requestID = null;

			//Convert Request Body from InputStream to String
			StringBuilder inputStringBuilder = new StringBuilder();
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(t.getRequestBody(), "UTF-8"));
			String line = bufferedReader.readLine();
			while(line != null){
				inputStringBuilder.append(line);
				inputStringBuilder.append('\n');
				line = bufferedReader.readLine();
			}
			request = inputStringBuilder.toString();
			
			System.out.println("Received Request. Message:" + request);

			//Getting the userID
			if(t.getRequestHeaders().containsKey("userID")){
				userID = t.getRequestHeaders().get("userID").toString();
			}


			//Getting the request type
			if(t.getRequestHeaders().containsKey("reqID")){
				requestID = t.getRequestHeaders().get("reqID").toString();
			} else {
				String res = "Missing request type";
				t.sendResponseHeaders(500, res.length());
				OutputStream os = t.getResponseBody();
				os.write(res.getBytes());
				os.close();
				return;
			}
			
			System.out.println("UserID:" + userID +", reqID:" + requestID);

			//Processing input and getting response
			String response = "";
			try {
				response = respond(userID, requestID, request);
			} catch (InvalidKeyException | NoSuchAlgorithmException
					| NoSuchPaddingException | IllegalBlockSizeException
					| BadPaddingException | InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}


			t.sendResponseHeaders(200, response.length());
			OutputStream os = t.getResponseBody();
			os.write(response.getBytes());
			os.close();
		}
	}

	/*
	 * This next method is where the server processes the request and generates a response
	 */
	private static String respond(String userID, String reqID, String request) 
			throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		String response = "RESPONSE";

		userData userInfo = null;
		if (userID != null) {
			userInfo = users.get(userID);

			if (userInfo == null) {
				return "BAD USER ID";
			}

			IvParameterSpec iv = null;

			byte[] encBytes = request.getBytes("UTF-8");

			int reqLength = encBytes.length - CryptoUtilities.IV_ENCRYPTED_LENGTH - CryptoUtilities.HMAC_LENGTH;
			byte[] encryptedIvBytes = new byte[CryptoUtilities.IV_ENCRYPTED_LENGTH];
			byte[] encryptedReqBytes = new byte[reqLength];
			byte[] hmacBytes = new byte[CryptoUtilities.HMAC_LENGTH];

			System.arraycopy(encBytes, 0, encryptedIvBytes, 0, CryptoUtilities.IV_ENCRYPTED_LENGTH);
			System.arraycopy(encBytes, CryptoUtilities.IV_ENCRYPTED_LENGTH, encryptedReqBytes, 
					0, reqLength);
			System.arraycopy(encBytes, reqLength + CryptoUtilities.IV_ENCRYPTED_LENGTH, hmacBytes, 
					0, CryptoUtilities.HMAC_LENGTH);



			try {
				//Get the IV
				byte[] ivBytes = CryptoUtilities.decryptData(encryptedIvBytes, userInfo.getPublicKey(), null);
				iv = new IvParameterSpec(ivBytes);

				//Decrypt the request
				//If the user has an unconfirmed session key, we need to try to decrypt it with the temp session key
				byte[] reqBytes;
				if( userInfo.getTempKey() != null && reqID.equals("confirmKeyChange")){
					reqBytes = CryptoUtilities.decryptData(encryptedReqBytes, userInfo.getTempKey(), iv);
				}else{
					reqBytes = CryptoUtilities.decryptData(encryptedReqBytes, userInfo.getSessionKey(), iv);
				}

				request = reqBytes.toString();

				//Check hmac digest
				String hk = CryptoUtilities.getHK(userInfo.getPreSharedKey(), userInfo.getSessionKey()),
						calculatedDigest = CryptoUtilities.hmacDigest(reqBytes, hk),
						receivedDigest = hmacBytes.toString();

				if( receivedDigest.equals(calculatedDigest)){
					System.out.println("Message integrity established.");
				}else{
					System.out.println("Message lacks integrity.");
					System.out.println("\tcalculated digest: " + calculatedDigest);
					System.out.println("\treceived digest: " + receivedDigest);
				}
			} catch (InvalidKeyException | NoSuchAlgorithmException
					| NoSuchPaddingException | IllegalBlockSizeException
					| BadPaddingException
					| InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}

		}

		// Needed to work with ajax post stuff, not sure if needed later
		reqID = reqID.substring(1, reqID.length()-1);
		if (userID != null)
			userID = userID.substring(1, userID.length()-1);

		switch (reqID) {

		case "initialize":
			byte[] byteString = new byte[40];
			random.nextBytes(byteString);
			String newID = new String(byteString);
			while (users.containsKey(newID)) {
				random.nextBytes(byteString);
				newID = new String(byteString);
			}


			break;

		case "reportConfidenceScores":

			String[] parts = request.split("/");

			if (parts.length != 2)
				return "BAD FORMAT";


			double score = Double.parseDouble(parts[0]);
			
			// TODO Not sure of the score here
			//if (score < .9) {
				//userInfo.lockAccount();
			//} 
			int TL = userInfo.isCompromised() ? -1 : TIMES_LEFT;
			
			String resString;
			// MAKE NEW SESSION KEY
			if (!userInfo.isSessionKeyValid()) {
				SecretKey newkey = CryptoUtilities.getSymmetricKey();
				userInfo.setTempKey(newkey);
				resString = newkey.toString() + "/" + parts[1] + "/" + TL;
			} else {
				resString = parts[1] + "/" + TL;
			}
			
			byte[] resbytes = resString.getBytes("UTF-8");
			IvParameterSpec i = CryptoUtilities.getNewIV();
			byte[] msg = CryptoUtilities.encryptData(resbytes, userInfo.getSessionKey(), i);
			byte[] encIV = CryptoUtilities.encryptData(i.toString().getBytes("UTF-8"), userInfo.getPublicKey(), null);
			byte[] hmac = CryptoUtilities.hmacDigest(resbytes, CryptoUtilities.getHK(userInfo.getSessionKey(), userInfo.getPreSharedKey())).getBytes("UTF-8");

			byte[] msg_to_send = new byte[msg.length+encIV.length+hmac.length];

			System.arraycopy(encIV, 0, msg_to_send, 0, encIV.length);
			System.arraycopy(msg, 0, msg_to_send, encIV.length, msg.length);
			System.arraycopy(hmac, 0, msg_to_send, encIV.length+msg.length, hmac.length);

			response = new String(msg_to_send);
			break;

		case "confirmKeyChange":
			String[] confirmationparts = request.split("/");

			if (confirmationparts.length != 2)
				return "BAD FORMAT";
			
			if (confirmationparts[0] == "CONFIRM") {
				userInfo.setSessionKey();
				response = "SESSION KEY CHANGED";
			} else {
				return "NO CONFIRMATION";
			}
			
			break;


		default:
			response = "BAD REQUEST TYPE";
			break;	
		}


		return response;
	}

	//Log Confidence Scores
	private static void log(String filename, String log) throws IOException{
		String file = LOG_FILE_PATH + filename;
		BufferedWriter writer = new BufferedWriter( new FileWriter( file ));
		writer.write(log);
		writer.close();
	}

	/*
	 * Next, I created a small userData class to allow storing user information easily using Map<String, userData>
	 * UserData contains the user's:
	 *        - Name
	 *        - Public Key
	 *        - Session Key
	 *        - Expiration Date
	 *        - PreShared Key
	 *        
	 */
	private class userData{
		private String name;
		private PublicKey publicKey;
		private SecretKey psk, sk, tempsk;
		private long expDate;
		private static final long validTime = 86400000; //1 day
		private boolean compromised = false;

		public userData(String uname, PublicKey pubKey, SecretKey PSK){
			name = uname;
			publicKey = pubKey;
			psk = PSK;
		}

		public String getName(){
			return name;
		}

		public PublicKey getPublicKey(){
			return publicKey;
		}

		public SecretKey getPreSharedKey(){
			return psk;
		}

		public SecretKey getSessionKey(){
			//assert(isSessionKeyValid());
			return sk;
		}

		public boolean isSessionKeyValid(){
			return System.currentTimeMillis() < expDate;//I used System.currentTimeMillis() as it does not require
			// a new object ( like new Date().getTime() )
		}
		
		public void setTempKey(SecretKey newKey) {
			tempsk = newKey;
		}
		
		public SecretKey getTempKey() {
			return tempsk;
		}

		public void setSessionKey(){
			sk = tempsk;
			tempsk = null;
			expDate = System.currentTimeMillis() + validTime;
		}

		public boolean isCompromised(){
			return compromised;
		}
		
		public void lockAccount(){
			compromised = true;
			expDate = -1; //Need to change session key when unlocked
		}
		
		public void unlockAccount(){
			compromised = false;
		}

	}
}