package edu.vanderbilt.cs285.app;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Hashtable;

import android.os.Bundle;
import android.app.Activity;
import android.view.Menu;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

public class DemoActivity extends Activity {
	public static final String serverURLString = "10.0.2.2"; // Emulator Uses 10.0.2.2 for localhost
	public int checksLeft = 10; 
	TextView console = null;
	TextView timesleft= null;
	URL serverURL = null; 
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		//console  = getResources()  // Find view from id text_console
		//timesleft = getResources()  // Find view from id text_model_checks_left
		//setContentView(.layout.activity_demo);
		
		try {
			serverURL = new URL(serverURLString);
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		//getMenuInflater().inflate(.menu.demo, menu);
		return true;
	}
	
	
	public void cantConnect() {
		Toast.makeText(this, "Cannot connect to the server! \nURL:" + serverURLString, 
				Toast.LENGTH_SHORT).show();
	}
	
	public void writeToConsole(String msg) {
		console.setText(console.getText() + "\n" + msg);
	}
	

	public void btn_init_onclick(View view)  
	{  
		Toast.makeText(this, "Initialize Button clicked!", Toast.LENGTH_SHORT).show();
	    
	}  
	
	public void btn_unencrypt_onclick(View view)  
	{  
	    Toast.makeText(this, "Test Unecrypt Button clicked!", Toast.LENGTH_SHORT).show();
	    
	    if(false == Network.canConnectToServer(serverURLString))
	    	cantConnect();
	    
	    HttpPostRequest req = new HttpPostRequest();
	    Hashtable<String, String> params = new Hashtable<String, String>();
	    params.put("userID", "bdraff");
	    params.put("checksleft", checksLeft+"");
	    params.put("timestamp", System.currentTimeMillis()+"");
	    writeToConsole("Sending to " + serverURLString + ": " + params.toString() + "... ");
	    String response = req.send(serverURLString, params);
	    writeToConsole("Response Received. msg: " + response);
	    
	    
	}  

	public void btn_encrypt_onclick(View view)  
	{  
	    Toast.makeText(this, "Test Encrypt Button clicked!", Toast.LENGTH_SHORT).show();  
	}  

	public void btn_success_onclick(View view)  
	{  
	    Toast.makeText(this, "Success Button clicked!", Toast.LENGTH_SHORT).show();  
	}  

	public void btn_alarm_onclick(View view)  
	{  
	    Toast.makeText(this, "Alarm Button clicked!", Toast.LENGTH_SHORT).show();  
	}  
	
}
