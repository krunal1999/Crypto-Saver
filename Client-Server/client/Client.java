import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/*
 * generating Aes keys with Server.pub and freshBytesOfClient and then encrpting them with Rsa. Converting new encrypted AES key to hex String and returning string.
 */

class GenratingAesKeyForServer {
	private PublicKey key;
	private byte[] raw;

	GenratingAesKeyForServer() throws FileNotFoundException, ClassNotFoundException, IOException {
		readPublicFileOfServer();
	}

	public void readPublicFileOfServer() throws FileNotFoundException, IOException, ClassNotFoundException {
		ObjectInputStream in = new ObjectInputStream(new FileInputStream("server.pub"));
		key = (PublicKey) in.readObject();
		in.close();
	}

	public String encryptWithRsa(byte[] msg) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		raw = cipher.doFinal(msg);
		System.out.println("Generated AES Key ");

		// convert byte[] to string and return
		StringBuilder sb = new StringBuilder();
		for (byte b : raw)
			sb.append(String.format("%02X", b));
		String s = sb.toString();
		// System.out.println(s);
		return s;
	}

}

/*
 * generating signature using client private key and freshBytesOfClient
 * converting signature to hex string and return hex string
 * 
 */
class SendSigToServer {
	private PrivateKey privateKey;

	public SendSigToServer(String username) throws Exception {
		getPvtKeyOfUser(username);
	}

	public void getPvtKeyOfUser(String username) throws Exception {
		ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(username + ".prv"));
		privateKey = (PrivateKey) keyIn.readObject();
		keyIn.close();
	}

	public String createSigWithPvtKey(String freshstr) throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initSign(privateKey);
		sig.update(freshstr.getBytes());
		byte[] signature = sig.sign();

		System.out.println("Generated Signature");

		// convert byte[] to string and return
		StringBuilder sb = new StringBuilder();
		for (byte b : signature)
			sb.append(String.format("%02X", b));
		String s = sb.toString();
		// System.out.println(s);
		return s;

	}
}

/*
 * Decrypt hes String to AES key
 */
class DecreyptAesKeySendByServer {

	public PrivateKey key;
	public byte[] raw;

	DecreyptAesKeySendByServer(String username) throws Exception {
		readPrivateKey(username);
	}

	// read key
	public void readPrivateKey(String username) throws Exception {
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(username + ".prv"));
		key = (PrivateKey) in.readObject();
		in.close();
		// readEncryptedFile();

	}

	public String decryptEncryptedFile(byte[] x) throws Exception {
		// decrypt
		raw = x;
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] stringBytes = cipher.doFinal(raw);
		String result = new String(stringBytes, "UTF8");
		// System.out.println(result);
		return result;
	}

}
/*
 * verify signature from server
 */
class verifySigOfServer {
	public boolean verifySig(byte[] sig1, String y) throws Exception {

		ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream("server.pub"));
		PublicKey publicKey = (PublicKey) keyIn.readObject();

		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(publicKey);
		sig.update(y.getBytes());

		boolean b = sig.verify(sig1);
		keyIn.close();
		if (b)return true;
		else return false;
	}

}
/*
 * Generate 32 byte Aes key
 */
class GenerateAesKey {

	public SecretKey generateAesKeyForServer(byte[] key) {

		SecretKey aesKey = new SecretKeySpec(key, "AES");
		return aesKey;

	}

}
/*
 * Encrpyting/Decrypting File with 32 Bytes Aes Key + Client random bytes
 */
class EncryptFileUsingAes {

	public void encryptFile(SecretKey key, byte[] iv , String filename , String md5Filename
			) throws Exception {


		IvParameterSpec ivspec = new IvParameterSpec(iv);   
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key , ivspec);
		FileInputStream inputStream = new FileInputStream(filename);
		FileOutputStream outputStream = new FileOutputStream(md5Filename);

		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				outputStream.write(output);
			}
		}
		byte[] outputBytes = cipher.doFinal();
		if (outputBytes != null) {
			outputStream.write(outputBytes);
		}
		inputStream.close();
		outputStream.close();

	}


	public void dencryptFile(SecretKey key, byte[] iv , String filename, String md5Filename
			) throws Exception {


		IvParameterSpec ivspec = new IvParameterSpec(iv);   
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key , ivspec);
		FileInputStream inputStream = new FileInputStream(md5Filename);
		FileOutputStream outputStream = new FileOutputStream("b1.txt");

		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				outputStream.write(output);
			}
		}
		byte[] outputBytes = cipher.doFinal();
		if (outputBytes != null) {
			outputStream.write(outputBytes);
		}
		inputStream.close();
		outputStream.close();
	}
}


public class Client {

	public static void main(String[] args) throws Exception {

		Socket s;
		String host = args[0];
		int port = Integer.parseInt(args[1]);
		String username = args[2];
		String filename = args[3];

		String filenameWithMD5 = username + ":gfhk7346:" + filename;
		
		//Converting original filename to MD5
		filenameWithMD5 = getMd5String(filenameWithMD5);
		
		s = new Socket(host, port);

		DataOutputStream dos = new DataOutputStream(s.getOutputStream());
		DataInputStream dis = new DataInputStream(s.getInputStream());
		

		// passing filename and username to server
		dos.writeUTF(username);
		dos.writeUTF(filename);

		// checking connection , waiting for reply from server
		// print connected to the server
		System.out.println(dis.readUTF());




		// //generating 16 fresh random bytes
		byte[] msg = new byte[128/8];
		SecureRandom.getInstanceStrong().nextBytes(msg);

		StringBuilder sb = new StringBuilder();
		for (byte b : msg) sb.append(String.format("%02X", b));

		// client Fresh bytes 
		String freshBytesOfClient = sb.toString();
		
		// I create msg[] of 16 bytes, but when converted to string its size increases to 32 bytes. I have maintain size for IV.
		//Random Bytes are used in RSA , AES encrypt and AES decrypt
		byte[] msg1 = freshBytesOfClient.getBytes("UTF8");

		// msg2 is used for IV in Aes Encryption
		byte[] msg2 = new byte[128/8];
		for(int i=0; i<16; i++){
			msg2[i] = msg1[i];
		}		
		
		System.out.println("-----New Bytes genrated -----");
		System.out.println(Arrays.toString(msg2));
		

		//-----------------------------------Step-1--------------------------------
		// Genrating Aes Keys for server
		GenratingAesKeyForServer genAesKeyForServer = new GenratingAesKeyForServer();

		// Genrating signature to server
		SendSigToServer sendSigToserver = new SendSigToServer(username);

		// Sending Aes encrypyted keys of Client to server
		dos.writeUTF(genAesKeyForServer.encryptWithRsa(msg1));
	
		// sending Signature to server
		dos.writeUTF(sendSigToserver.createSigWithPvtKey(freshBytesOfClient));

		//verify signature
		String checkSig = dis.readUTF();
		if(checkSig.equals("failed")) System.exit(0);





		//-----------------------------------Step-2--------------------------------
		// Getting Aes key from server and verify them.
		String readAesKeySendByServer, readSignatureSendByServer;

		readAesKeySendByServer = dis.readUTF();
		readSignatureSendByServer = dis.readUTF();

		// converting hex string passed by server to Byte[]
		byte[] aesKeyFromServer = convertStrToHEx(readAesKeySendByServer);
		byte[] signatureOfServer = convertStrToHEx(readSignatureSendByServer);

		// Decrpting Aes keys send by server and FreshBytesOfserver 
		DecreyptAesKeySendByServer dcyAesKeySendByServer = new DecreyptAesKeySendByServer(username);
		String aesKeyOfServer = dcyAesKeySendByServer.decryptEncryptedFile(aesKeyFromServer);


		try{ 
		// verfity the signature send by server with FreshBytesOfserver and server
		// public key
		verifySigOfServer verifySigOfServer = new verifySigOfServer();
		boolean status = verifySigOfServer.verifySig(signatureOfServer, aesKeyOfServer);

		if(status) System.out.println("Signature Verified");

		else{
			System.out.println("Signature Not Verified");
			System.exit(0);
		}
		
		} catch(Exception e){
			System.out.println("Connection Closed by Client");
		}





		//-----------------------------------Step-3--------------------------------
		// creating 32 byte Aes key to encrypt File
		String aes32 = aesKeyOfServer.concat(freshBytesOfClient);
		byte[] aes32toBytes = convertStrToHEx(aes32);

		//System.out.println("Aes Key -- " + aes32);
		//System.out.println("");


		// genrating Aes key 256 bit
		GenerateAesKey generateAesKey = new GenerateAesKey();
		SecretKey key = generateAesKey.generateAesKeyForServer(aes32toBytes);



		//-----------------------------------Step-4--------------------------------
		// encrypting file with Aes Key
		EncryptFileUsingAes aesEnc = new EncryptFileUsingAes();
		
		aesEnc.encryptFile(key, msg2 , filename,filenameWithMD5);
		//aesEnc.dencryptFile(key, msg2 , filename,filenameWithMD5);


		System.out.println("----------");
		System.out.println(key);
		System.out.println(Arrays.toString(msg2));

		System.out.println("----------");



		//-----------------------------------Step-5--------------------------------
		//send encrpyted file with md5 hashing to server
		//FileInputStream fis = new FileInputStream(filenameWithMD5);
		System.out.println("Sending File " +filenameWithMD5);
		dos.writeUTF(filenameWithMD5);
		sendFiletoServer(filenameWithMD5, dos);
		
		
		s.close();
		

	}

	// convert string to Hex
	public static byte[] convertStrToHEx(String x) {
		byte[] val = new byte[x.length() / 2];
		for (int i = 0; i < val.length; i++) {
			int index = i * 2;
			int j = Integer.parseInt(x.substring(index, index + 2), 16);
			val[i] = (byte) j;
		}
		return val;

	}
	//convert string to MD5
	public static String getMd5String(String filename) throws Exception{

		byte[] md5byte = filename.getBytes("UTF8");
		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] md5Digest = md.digest(md5byte);

                StringBuilder sb = new StringBuilder();
                for (byte b : md5Digest) sb.append(String.format("%02x", b));

		String fileNameWithMD5 = sb.toString();

		return fileNameWithMD5;

	}

	// Send file to the server I took reference from internet for below code
	public static void sendFiletoServer(String filenameWithMd5 , DataOutputStream dos) throws Exception{

		int bytes = 0;
		File file = new File(filenameWithMd5);
		FileInputStream fileInputStream= new FileInputStream(file);
	 
		dos.writeLong(file.length());
	
		byte[] buffer = new byte[8 * 1024];
		while ((bytes = fileInputStream.read(buffer))!= -1) {
		
		  dos.write(buffer, 0, bytes);
		  dos.flush();
		}
		
		System.out.println("File send to Server");
		fileInputStream.close();

	}
	public static void closeConnection() throws Exception{
		System.out.println("Client Close Connection");
		
	}

}

// javac Client.java
// java Client localhost 1234 kbd6 secret,jpg