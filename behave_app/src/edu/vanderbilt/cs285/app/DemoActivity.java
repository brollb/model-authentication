package edu.vanderbilt.cs285.app;

import android.os.Bundle;
import android.app.Activity;
import android.view.Menu;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

public class DemoActivity extends Activity {
	public static final String DEFAULT_USER = "DEFAULT_USER";
	TextView console = null;
	TextView timesleft;
	Networking net = null;

	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_demo);
		console = (TextView)findViewById(R.id.text_console);
		timesleft = (TextView)findViewById(R.id.text_model_checks_left);
		net = new Networking(this);
		
		// Set Initial checks left to 0 for safety
		updateChecksLeft(0);
		
		
		writeToConsole("System Started. Not connected to server");
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.demo, menu);
		return true;
	}
	
//	/**
//	 * Display an error message if we cannot connect to the server
//	 */
//	public void cantConnect() {
//		Toast.makeText(this, "Cannot connect to the server! \nURL:" + serverURLString, 
//				Toast.LENGTH_SHORT).show();
//	}
	
	/**
	 * Convenience method that writes to the on-screen 'console'
	 * @param msg Message to be added to the beginning of the console
	 */
	public void writeToConsole(final String msg) {
	    DemoActivity.this.runOnUiThread(new Runnable() {
	    	public void run() {
	    		try {
	    			console.setText(msg + "\n" + console.getText());
	    		} catch(Exception e){}
	    	}
	    });
	}
	
	/**
	 * Updates the number of remaining model checks allowed and displays result onscreen
	 */
	public void updateChecksLeft(final int checksLeft) {
		DemoActivity.this.runOnUiThread(new Runnable() {
	    	public void run() {
	    		try {
	    			timesleft.setText(checksLeft + "");
	    		} catch(Exception e){}
	    	}
	    });
		
	}

	public void btn_init_onclick(View view)  
	{  
		Toast.makeText(this, "Initialize Button clicked!", Toast.LENGTH_SHORT).show();
	    
	}  
	
//	public void postData() {
//	    // Create a new HttpClient and Post Header
//	    HttpClient httpclient = new DefaultHttpClient();
//	    HttpPost httppost = new HttpPost(serverURLString);
//
//	    try {
//	        // Add your data
//	        List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(2);
//	        nameValuePairs.add(new BasicNameValuePair("id", "12345"));
//	        nameValuePairs.add(new BasicNameValuePair("stringdata", "Hi"));
//	        httppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
//
//	        // Execute HTTP Post Request
//	        HttpResponse response = httpclient.execute(httppost);
//
//	    } catch (ClientProtocolException e) {
//	        // TODO Auto-generated catch block
//	    } catch (IOException e) {
//	        // TODO Auto-generated catch block
//	    }
//	} 
	
	public void btn_unencrypt_onclick(View view)  
	{  
	    final DemoActivity da = this;
		Toast.makeText(this, "Setting up encrypted connection with server" +
				"... Please wait", Toast.LENGTH_LONG).show();
		
		net.firstConnection(DEFAULT_USER, null);
		
		
	}  

	public void btn_encrypt_onclick(View view)  
	{  
	    //Toast.makeText(this, "Test Encrypt Button clicked!", Toast.LENGTH_SHORT).show();
	    
	    net.requestFirstSession(DEFAULT_USER);
	}  

	public void btn_success_onclick(View view)  
	{  
	    //Toast.makeText(this, "Success Button clicked!", Toast.LENGTH_SHORT).show();
	    
	    net.sendLogging(DEFAULT_USER, new int[]
	    		{((int)Math.random()*20),((int)Math.random()*20),((int)Math.random()*20)});
	}  

	public void btn_alarm_onclick(View view)  
	{  
	    //Toast.makeText(this, "Alarm Button clicked!", Toast.LENGTH_SHORT).show();
	    
	    //net.confirmNewSession(DEFAULT_USER, 0);
	    net.sendLogging(DEFAULT_USER, new int[]
	    		{(60 + (int)Math.random()*20),(60 + (int)Math.random()*20),(60 + (int)Math.random()*20)});
	}  
	
}
