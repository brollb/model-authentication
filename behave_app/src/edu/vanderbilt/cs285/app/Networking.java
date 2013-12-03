package edu.vanderbilt.cs285.app;

import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Hashtable;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import android.app.Activity;
import android.widget.Toast;



public class Networking {
	// the networking will ONLY function if this is running on an emulator
	public static final String serverURLString = "http://10.0.2.2:8000/test"; // Emulator Uses 10.0.2.2 for localhost
	URL serverURL = null;
	private int checksLeft = 10;
	private DemoActivity context_ = null;
	
	private SecretKey psk_;
	private KeyPair phoneKeys_; // Phone's Keypair
	private PublicKey serverPublicKey_;
	private Cipher symCipher_;
	private Cipher asymCipher_;
	private final String username_ = "TESTUSER";
	private IvParameterSpec iv_;
	
	
	public Networking(DemoActivity context) {
		context_ = context;
		CryptoUtilities.allowEncryption();
		// Set Initial checks left to 0 for safety
		checksLeft = 10; 
		
		try {
			serverURL = new URL(serverURLString);
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//if(canConnectToServer(serverURLString))
		//	context_.writeToConsole("Networking Started. Server Connection Established. Server URL: " + serverURLString);
		
	}
	
	public boolean canConnectToServer(String url) {
		try {
			URL mURL = new URL(url);
			HttpURLConnection conn = (HttpURLConnection) mURL.openConnection();
			conn.connect();
			conn.disconnect();

		} catch (Exception ex) {
			// Log.i(TAG, "Cannot connect to " + url);
			context_.writeToConsole("Networking Failure. Server URL: " + serverURLString);
			return false;
		}

		// Log.i(TAG, "Connection test to " + url + " succeeded.");
		return true;
	}
	
	public void firstConnection(final String username, final PublicKey serverPublic) {


	    new Thread() {
	    	public void run() {
	    
	    		try {
	    			
	    			if(serverPublic != null)
	    				serverPublicKey_ = serverPublic;
	    			else
	    				serverPublicKey_ = CryptoUtilities.getKeypair(true).getPublic();
	    			
	    			// Generate Phone Keypair
	    			
	    				phoneKeys_ = CryptoUtilities.getKeypair(false);
	    			} catch (NoSuchAlgorithmException e) {
	    				// TODO Auto-generated catch block
	    				e.printStackTrace();
	    			}
	    		
		    HttpPostRequest req = new HttpPostRequest();
		    Hashtable<String, String> headers = new Hashtable<String, String>();
		    Hashtable<String, String> params  = new Hashtable<String, String>();
		    // POST Parameters
		    //params.put("userID", "bdraff");
		    params.put("checksleft", checksLeft+"");
		    params.put("timestamp", System.currentTimeMillis()+"");
		    params.put("phonePublic", new String(phoneKeys_.getPublic().getEncoded()));
		    // Header Parameters
		    headers.put("userID", username);
		    headers.put("reqID", "initialize");
		    context_.writeToConsole("Sending to " + serverURLString + " -- Header: " + headers.toString() + " -- Params: " + params.toString() + "... ");
		    final String response = req.send(serverURLString, headers, params);
		    System.out.println("Server Response: " + response);
		    context_.writeToConsole("Response Received. msg: " + response);
		    
	    	}
	    }.start();
	    
	    // If I am setting up for the first time, set checks to 10
		context_.updateChecksLeft(checksLeft = 10);

		
	}
	
	
	public void requestFirstSession(final String username) {

	    new Thread() {
	    	public void run() {
	    
		    HttpPostRequest req = new HttpPostRequest();
		    Hashtable<String, String> headers = new Hashtable<String, String>();
		    Hashtable<String, String> params  = new Hashtable<String, String>();
		    // POST Parameters
		    //params.put("userID", "bdraff");
		    params.put("checksleft", checksLeft+"");
		    params.put("timestamp", System.currentTimeMillis()+"");
		    params.put("phonePublic", new String(phoneKeys_.getPublic().getEncoded()));
		    params.put("preshared", new String(psk_.getEncoded()));
		    // Header Parameters
		    headers.put("userID", username);
		    headers.put("reqID", "firstSession");
		    context_.writeToConsole("Sending to " + serverURLString + " -- Header: " + headers.toString() + " -- Params: " + params.toString() + "... ");
		    final String response = req.send(serverURLString, headers, params);
		    System.out.println("Server Response: " + response);
		    context_.writeToConsole("Response Received. msg: " + response);
		    
	    	}
	    }.start();
		
	}

	public void confirmNewSession(final String username, final long firstTimestamp) {

	    new Thread() {
	    	public void run() {
	    
		    HttpPostRequest req = new HttpPostRequest();
		    Hashtable<String, String> headers = new Hashtable<String, String>();
		    Hashtable<String, String> params  = new Hashtable<String, String>();
		    // POST Parameters
		    //params.put("userID", "bdraff");
		    params.put("timestamp", System.currentTimeMillis()+"");
		    params.put("firstTimestamp", firstTimestamp+"");
		    // Header Parameters
		    headers.put("userID", username);
		    headers.put("reqID", "confirmNewSession");
		    context_.writeToConsole("Sending to " + serverURLString + " -- Header: " + headers.toString() + " -- Params: " + params.toString() + "... ");
		    final String response = req.send(serverURLString, headers, params);
		    System.out.println("Server Response: " + response);
		    context_.writeToConsole("Response Received. msg: " + response);
		    
	    	}
	    }.start();
		
	}
	
	
	public void sendLogging(final String username, final int[] confidenceScores) {
		if(checksLeft <= 0) {
			Toast.makeText(context_, "No More Model Checks remaining.", Toast.LENGTH_SHORT).show();
			return;
		}
		
		// It will only connect while running on an emulator
	    //if(false == canConnectToServer(serverURLString))
	    //	return; // Message and logging already handled
	    
	    new Thread() {
	    	public void run() {
	    
		    HttpPostRequest req = new HttpPostRequest();
		    Hashtable<String, String> headers = new Hashtable<String, String>();
		    Hashtable<String, String> params  = new Hashtable<String, String>();
		    // POST Parameters
		    //params.put("userID", "bdraff");
		    params.put("checksleft", checksLeft+"");
		    params.put("timestamp", System.currentTimeMillis()+"");
		    params.put("recentData", intArrayToString(confidenceScores));
		    // Header Parameters
		    headers.put("userID", username);
		    headers.put("reqID", "reportConfidenceScores");
		    context_.writeToConsole("Sending to " + serverURLString + " -- Header: " + headers.toString() + " -- Params: " + params.toString() + "... ");
		    final String response = req.send(serverURLString, headers, params);
		    System.out.println("Server Response: " + response);
		    context_.writeToConsole("Response Received. msg: " + response);
		    
		    // If I am sending logging, that may mean the model has been checked.
			if(confidenceScores[0] < 30 && checksLeft == 1)
				context_.updateChecksLeft(checksLeft = 10);
			else
				context_.updateChecksLeft(--checksLeft);
			
	    	}
	    }.start();
	    
	}
	
	public void confirmMessage(long timestamp) {
		
	}
	
	/**
	 * Helper that stringifys an int array (ie recent confidences)
	 * @param ar
	 * @return
	 */
	public String intArrayToString(int[] ar) {
		if( ar == null)
			return "0";
		String ret = "";
		for(int i : ar) 
			ret += i + ",";
		return ret.substring(0, ret.length()-1);
	}
}
	