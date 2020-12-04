import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Scanner;

import javax.net.ssl.HttpsURLConnection;

public class Client {

	public static void main(String[] args) {
		// Build the basic http request
		// Manipulate headers to generate the signature
		// Send request and print response
		
		//default method get
		String method = "get";
		
		if(args.length > 0 && (args[0].equals("get" ) || args[0].equals("post" ) || args[0].equals("put" ) || args[0].equals("delete")))
			method = args[0];
		
		//declare fixed params
		//the following lines represent params that are always present	
		DateTimeFormatter dtf = DateTimeFormatter.RFC_1123_DATE_TIME;  
		String date = dtf.format(ZonedDateTime.now());
		String host = "staging.authservices.satispay.com";	
		String body = "{\"hello\": \"world\"}";
		String sign_construction = "(request-target): " + method + " /wally-services/protocol/tests/signature\n"
								+  "host: " + host + "\n"
								+  "date: " +  date;
		//headers
		String headers = "(request-target) host date";
												
		System.out.println("Satisclient");
		
		String string_url = "https://staging.authservices.satispay.com/wally-services/protocol/tests/signature";
		
		URL url = null;
		try {
			url = new URL(string_url);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			System.err.println("Malformed url, unable to make the request");
			System.exit(1);
		}
				
		//set up http connection
		HttpsURLConnection con = null;
		try {
			con = (HttpsURLConnection)url.openConnection();
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("Unable to make the request");
			System.exit(1);
		}
		
		try {
			con.setRequestMethod(method.toUpperCase());
		} catch (ProtocolException e) {
			e.printStackTrace();
			System.err.println("Wrong method");
			System.exit(1);
		}
		con.setRequestProperty("Host", host);
		con.setRequestProperty("Date", date);
			
		//sign with the key
		String signature = sign(sign_construction);		
		
		//add in the authorization fields
		String Authorization = "Signature keyId=\"signature-test-66289\",algorithm=\"rsa-sha256\", headers=\"" + headers +"\", signature=\"" + signature +"\"";
		con.setRequestProperty("Authorization", Authorization);
		
		//add digest in case the method is post or put 
		//in other cases the body of the request is empty
		if(method.equals("post") || method.equals("put")) {
			String digest = calcDigest(body);
			sign_construction += "\n" +  "digest: SHA-256=" + digest;
			headers += " digest";
			con.setRequestProperty("Digest", "SHA-256="+digest);
			con.setRequestProperty("Content-Type", "application/json;");
			con.setRequestProperty("Content-Length", Integer.toString(body.length()));
			
			signature = sign(sign_construction);
			Authorization = "Signature keyId=\"signature-test-66289\",algorithm=\"rsa-sha256\", headers=\"" + headers +"\", signature=\"" + signature +"\"";
			con.setRequestProperty("Authorization", Authorization);
			//Write in the body
			con.setDoOutput(true);
			OutputStream os;
			try {
				os = con.getOutputStream();
				OutputStreamWriter osw = new OutputStreamWriter(os, "UTF-8");    
				osw.write(body);
				osw.flush();
				osw.close();
				os.close();
			} catch (IOException e) {
				e.printStackTrace();
				System.err.println("Error while writing the body of the request");
				System.exit(1);
			}
			
		}
			
		//print response
		try {
			print_content(con);
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("Error while reading the response");
			System.exit(1);
		}
		
		con.disconnect();
		  	
	}
	
	static private void print_content(HttpsURLConnection con) throws IOException{
		
		int response = con.getResponseCode();
	    if(con!=null &&  response == 200){ 
	             
	       System.out.println("Response code: " + response);
	       System.out.println("Response:");			
	       BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
	                
	       String input;
	                
	       while ((input = br.readLine()) != null){
	          System.out.println(input);
	       }
	       br.close();
	                
	       }
	        
	   }
	
	static private String sign(String input)  {
		//throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException, UnsupportedEncodingException
		String key = "";
		String file =  "Resources/client-rsa-private-key.pem";
		//read from file
		try {
			File f = new File(file);
			Scanner read = new Scanner(f);
			while(read.hasNextLine())
				key += read.nextLine();
		}
		catch (FileNotFoundException e) {
			e.printStackTrace();
			System.err.println("Not found " + file + "file");
			System.exit(1);
		}
				
		String ris = "";
		String k = key.replaceAll("-----BEGIN PRIVATE KEY-----", "").replaceAll("-----END PRIVATE KEY-----","").replaceAll(" ","").replaceAll("\n", "");
		//System.out.println(k);
		
		//Decode base64
		byte[] b1 = Base64.getDecoder().decode(k);
		byte[] s = null;
		
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b1);
		KeyFactory kf = null;
		Signature privateSignature = null;
		try {
			kf = KeyFactory.getInstance("RSA");
			privateSignature = Signature.getInstance("SHA256withRSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.err.println("No such algorithm");
			System.exit(1);
		}
		
		try {
			privateSignature.initSign(kf.generatePrivate(spec));	
		} catch (InvalidKeyException | InvalidKeySpecException e) {
			e.printStackTrace();
			System.err.println("InvalidKeyException or InvalidKeySpecException");
			System.exit(1);
		}
		
		try {
			privateSignature.update(input.getBytes("UTF-8"));
			s = privateSignature.sign();
		} catch (SignatureException | UnsupportedEncodingException e) {
			e.printStackTrace();
			System.err.println("SignatureException or UnsupportedEncodingException");
			System.exit(1);
		}

        //Encode to base64 and return
        return Base64.getEncoder().encodeToString(s);
        
	}
	
	static private String calcDigest(String data){
		
		MessageDigest digest = null;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.err.println("No such algorithm");
			System.exit(1);		
		}
		byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
		
		return Base64.getEncoder().encodeToString(hash);
	}
	
}
