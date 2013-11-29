package edu.vanderbilt.cs285.utilities;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

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
	private static final int SERVER_PORT = 8000;
	private static Map<String, userData> users = new HashMap<String, userData>();

	    public static void initialize() throws Exception {
	        HttpServer server = HttpServer.create(new InetSocketAddress(SERVER_PORT), 0);
	        server.createContext("/test", new MyHandler());
	        server.setExecutor(null); // creates a default executor
	        CryptoUtilities.allowEncryption();//allows the server to use heavy encryption algorithms and key sizes
	        server.start();
	    }

	    static class MyHandler implements HttpHandler {
	        public void handle(HttpExchange t) throws IOException {
	            if(t.getRequestMethod().equals("GET")) //Only respond to POST requests
	            	return;

	            String response = "This is the response\n";//Temporary content for testing
	            response += "Request Method: " + t.getRequestMethod();

	            t.sendResponseHeaders(200, response.length());
	            OutputStream os = t.getResponseBody();
	            os.write(response.getBytes());
	            os.close();
	        }
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
	    	private Key publicKey, psk, sk;
	    	private long expDate;
	    	private static final long validTime = 86400000; //1 day

	    	public userData(String uname, Key pubKey, Key PSK){
	    		name = uname;
	    		publicKey = pubKey;
	    		psk = PSK;
	    	}
	    	
	    	public String getName(){
	    		return name;
	    	}
	    	
	    	public Key getPublicKey(){
	    		return publicKey;
	    	}
	    	
	    	public Key getPreSharedKey(){
	    		return psk;
	    	}

	    	public Key getSessionKey(){
	    		assert(isSessionKeyValid());
	    		return sk;
	    	}
	    	
	    	public boolean isSessionKeyValid(){
	    		return System.currentTimeMillis() < expDate;//I used System.currentTimeMillis() as it does not require
	    													// a new object ( like new Date().getTime() )
	    	}
	    	
	    	public void setSessionKey(Key newSessionKey){
	    		sk = newSessionKey;
	    		expDate = System.currentTimeMillis() + validTime;
	    	}
	    }
}