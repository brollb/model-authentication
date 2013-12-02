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
	// the networking will ONLY function if this is running on an emulator
	public static final String serverURLString = "http://10.0.2.2:8000/test"; // Emulator Uses 10.0.2.2 for localhost
	public int checksLeft = 10; 
	TextView console = null;
	TextView timesleft= null;
	URL serverURL = null; 
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_demo);
		console = (TextView)findViewById(R.id.text_console);
		timesleft = (TextView)findViewById(R.id.text_model_checks_left);
		
		try {
			serverURL = new URL(serverURLString);
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		timesleft.setText(checksLeft + "");
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.demo, menu);
		return true;
	}
	
	
	public void cantConnect() {
		Toast.makeText(this, "Cannot connect to the server! \nURL:" + serverURLString, 
				Toast.LENGTH_SHORT).show();
	}
	
	public void writeToConsole(final String msg) {
	    DemoActivity.this.runOnUiThread(new Runnable() {
	    	public void run() {
	    		try {
	    			console.setText(msg + "\n" + console.getText());
	    		} catch(Exception e){}
	    	}
	    });
	}
	
	public void decrementChecksLeft() {
		checksLeft--;
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
		Toast.makeText(this, "Test Unecrypt Button clicked!", Toast.LENGTH_SHORT).show();
	    
		// It will only connect while running on an emulator
	    if(false == Network.canConnectToServer(serverURLString))
	    	cantConnect();
	    
	    new Thread() {
	    	public void run() {
	    
		    HttpPostRequest req = new HttpPostRequest();
		    Hashtable<String, String> params = new Hashtable<String, String>();
		    
		    // POST Parameters
		    params.put("userID", "bdraff");
		    params.put("checksleft", checksLeft+"");
		    params.put("timestamp", System.currentTimeMillis()+"");
		    writeToConsole("Sending to " + serverURLString + ": " + params.toString() + "... ");
		    final String response = req.send(serverURLString, params);
		    System.out.println("Server Response: " + response);
		    writeToConsole("Response Received. msg: " + response);
		    decrementChecksLeft();
	    	}
	    }.start();
	    
	    
	    
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
