//package edu.vanderbilt.cs285.utilities;

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
	        System.out.println("Listening on: " + server.getAddress().toString().substring(1));
	        System.out.println("\n\n");
	        server.createContext("/test", new MyHandler());
	        server.setExecutor(null); // creates a default executor
	        CryptoUtilities.allowEncryption();//allows the server to use heavy encryption algorithms and key sizes
	        keyPair = CryptoUtilities.getKeypair(true);
	        server.start();
	        
	       /* Key k = CryptoUtilities.getSymmetricKey();
	        IvParameterSpec iv = CryptoUtilities.getNewIV();
	        byte[] b = CryptoUtilities.encryptData((new String("testtesttesttest")).getBytes(), k, iv);
	        System.out.println("E length: "+b.length);
	        byte[] h = CryptoUtilities.decryptData(b, k, iv);
	        System.out.println("D length: "+h.length);*/
	        
	        KeyPair k = CryptoUtilities.getKeypair(false);
	        IvParameterSpec iv = CryptoUtilities.getNewIV();
	        byte[] b = CryptoUtilities.encryptData(iv.getIV(), k.getPublic(), iv);
	        System.out.println("E length: "+b.length);
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
	            String type = null;
	            
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

	            //Getting the userID
	            if( t.getRequestHeaders().containsKey("userID")){
	            	userID = t.getRequestHeaders().get("userID").toString();
	            }
	            
	            //Getting the request type
	            if(t.getRequestHeaders().containsKey("requestID")){
	            	type = t.getRequestHeaders().get("requestID").toString();
	            } else {
	            	String res = "Missing request type";
	            	t.sendResponseHeaders(500, res.length());
	            	OutputStream os = t.getResponseBody();
		            os.write(res.getBytes());
		            os.close();
	            	return;
	            }

	            //Processing input and getting response
	            String response = respond(type, userID, request);

	            t.sendResponseHeaders(200, response.length());
	            OutputStream os = t.getResponseBody();
	            os.write(response.getBytes());
	            os.close();
	        }
	    }
	    
	    /*
	     * This next method is where the server processes the request and generates a response
	     */
	    private static String respond(String type, String userID, String request) {
	    	String response = "RESPONSE";
	    	
	    	byte[] requestBytes = request.getBytes();
	    	
	    	// Needed to work with ajax post stuff, not sure if needed later
	    	type = type.substring(1, type.length()-1);
	    	if (userID != null)
	    		userID = userID.substring(1, userID.length()-1);
	    	//System.out.println(type);
	    	switch (type) {
	    	
	    	case "initialize":
	    		byte[] byteString = new byte[40];
	    		random.nextBytes(byteString);
				String newID = new String(byteString);
				while (users.containsKey(newID)) {
					random.nextBytes(byteString);
					newID = new String(byteString);
				}
				
	    		break;
	    		
	    	case "normal":
	    		userData mUserdata = users.get(userID);
	    		if (mUserdata == null) {
	    			return "BAD USERID";
	    		}
	    		
	    		// NEED TO CHANGE IF SIZES CHANGE
	    		
	    		byte[] ivEncrypted = new byte[128];
	    		
	    		
	    		int tl = 0;
	    		
	    		if (mUserdata.isSessionKeyValid()) {
	    			byte[] msg = null;
	    		} else {
	    			//byte[] ret = CryptoUtilities.getNewSessionResponse(mUserdata.getPublicKey(), mUserdata.getSessionKey(), 0);
	    		}
	    		break;
	    		
	    	case "confirm_new_sk":
	    		
	    		break;
	    		
	    		
	    	// More here?
	    	
	    		
	    		
	    	default:
	    		response = "BAD REQUEST TYPE";
	    		break;	
	    	}
	    	
	    	//TODO handle the user request for more 'Times Left'

	    	//TODO Build appropriate response

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
	    	private SecretKey psk, sk;
	    	private long expDate;
	    	private static final long validTime = 86400000; //1 day

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
	    	
	    	public void setSessionKey(SecretKey newSessionKey){
	    		sk = newSessionKey;
	    		expDate = System.currentTimeMillis() + validTime;
	    	}
	    }
}