import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
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
 * Decrypt hes String to AES key
 */
class DecreyptAesKeySendByClient {

	public PrivateKey key;
	public byte[] raw;

	DecreyptAesKeySendByClient() throws Exception {
		readPrivateKey();
	}

	// read key
	public void readPrivateKey() throws Exception {
		ObjectInputStream in = new ObjectInputStream(new FileInputStream("server.prv"));
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
		System.out.println(result);
		return result;
	}

}
/*
 * verify signature from client
 */
class verifySigOfClient {

	public boolean verifySig(byte[] sig1, String y, String username) throws Exception {

		ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(username + ".pub"));
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
 * generating Aes keys with client.pub and freshBytesOfServer and then encrpting them with Rsa. 
 * Converting new encrypted AES key to hex String and returning string.
 */
class GenratingAesKeyForClient {
	PublicKey key;
	byte[] raw;

	GenratingAesKeyForClient(String username) throws FileNotFoundException, ClassNotFoundException, IOException {
		readPublicFileOfServer(username);
	}

	public void readPublicFileOfServer(String username)
			throws FileNotFoundException, IOException, ClassNotFoundException {
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(username + ".pub"));
		key = (PublicKey) in.readObject();
		in.close();
	}

	public String encryptWithRsa(byte[] msg) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		raw = cipher.doFinal(msg);
		System.out.println("Generated Aes Key");

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
 * generating signature using Server private key and freshBytesOfServer
 * converting signature to hex string and return hex string
 * 
 */
class SendSigToClient {
	public PrivateKey privateKey;

	public SendSigToClient() throws Exception {
		getPvtKeyOfUser();
	}

	public void getPvtKeyOfUser() throws Exception {
		ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream("server.prv"));
		privateKey = (PrivateKey) keyIn.readObject();
		keyIn.close();
	}

	public String createSigWithPvtKey(String freshstr) throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initSign(privateKey);
		sig.update(freshstr.getBytes());
		byte[] signature = sig.sign();
		System.out.println("Genrated Sig");

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
 * Decrypting File with 32 Bytes Aes Key + Client random bytes
 */
class DecrpytFileUsingAes {

	public void dencryptFile(SecretKey key, byte[] iv  , String md5Filename
			) throws Exception {


		IvParameterSpec ivspec = new IvParameterSpec(iv);   
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key , ivspec);
		FileInputStream inputStream = new FileInputStream(md5Filename);
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

class Server {

	public static void main(String[] args) throws Exception {

		String username = null;
		String filename = null;
		int port = Integer.parseInt(args[0]); // 1111

		ServerSocket ss = new ServerSocket(port);
		System.out.println("Waiting incoming connection...");

		while (true) {
			Socket s = ss.accept();
			DataInputStream dis = new DataInputStream(s.getInputStream());
			DataOutputStream dos = new DataOutputStream(s.getOutputStream());

			// reading username and filename
			try {
				username = dis.readUTF();
				filename = dis.readUTF();
				System.out.println(username + " is Connected to server");
				dos.writeUTF("Connected to the server");

				// //generating 16 fresh random bytes
				byte[] msg = new byte[128 / 8];
				SecureRandom.getInstanceStrong().nextBytes(msg);
				StringBuilder sb = new StringBuilder();
				for (byte b : msg)
					sb.append(String.format("%02X", b));

				String freshBytesOfServer = sb.toString();

				byte[] msg1 = freshBytesOfServer.getBytes("UTF8");

				// System.out.println(Arrays.toString(msg));
				System.out.println("New Bytes genrated");



				// to read aes key send by client
				String readAesKeySendByClient, readSignatureSendByClient;
				readAesKeySendByClient = dis.readUTF();
				readSignatureSendByClient = dis.readUTF();

				// converting string passed by client to Byte[]
				byte[] aesKeyFromClient = convertStrToHEx(readAesKeySendByClient);
				byte[] signature = convertStrToHEx(readSignatureSendByClient);

				
				// decrypt Aes Key send by Client
				DecreyptAesKeySendByClient dcyAesKeySendByClient = new DecreyptAesKeySendByClient();
				String aesKeyOfClient = dcyAesKeySendByClient.decryptEncryptedFile(aesKeyFromClient);

				

				// accept signature
				try{ 
				verifySigOfClient verifySigOfClient = new verifySigOfClient();
				boolean status = verifySigOfClient.verifySig(signature, aesKeyOfClient, username);

				if(status) 
				{
					System.out.println("Signature Verified");
					dos.writeUTF("passed");
				}
				else{
						System.out.println("Signature Not Verified");
						dos.writeUTF("failed");
						continue;
				}
				
				} catch(Exception e){

						System.out.println("Connection Closed by Client");
					}



				GenratingAesKeyForClient genAesKeyForClient = new GenratingAesKeyForClient(username);
				SendSigToClient sendSigToClient = new SendSigToClient();


				dos.writeUTF(genAesKeyForClient.encryptWithRsa(msg1));
				dos.writeUTF(sendSigToClient.createSigWithPvtKey(freshBytesOfServer));

				// creating 32 byte Aes key to encrypt File
				String aes32 = freshBytesOfServer.concat(aesKeyOfClient);
				byte[] aes32toBytes = convertStrToHEx(aes32);

				GenerateAesKey generateAesKey = new GenerateAesKey();
				SecretKey key = generateAesKey.generateAesKeyForServer(aes32toBytes);

				byte[] msg4;
				msg4 = aesKeyOfClient.getBytes("UTF8");
				System.out.println(Arrays.toString(msg4));

				byte[] msg2 = new byte[128/8];
					for(int i=0; i<16; i++){
						msg2[i] = msg4[i];
				}		


				// recieve file name
				String filenameWithMD5 = dis.readUTF();

				receiveFileFromClient(filenameWithMD5 , dis);
				System.out.println("file received  " + filenameWithMD5);



				DecrpytFileUsingAes sesDec = new DecrpytFileUsingAes();
				sesDec.dencryptFile(key, msg2 ,filenameWithMD5);

				System.out.println("------------------------------------");
				System.out.println("Waiting for the connection ....");
				System.out.println("");




			} catch (IOException e) {
				System.err.println("Connection Closed by client");
			}
		}

	}

	public static byte[] convertStrToHEx(String x) {
		byte[] val = new byte[x.length() / 2];
		for (int i = 0; i < val.length; i++) {
			int index = i * 2;
			int j = Integer.parseInt(x.substring(index, index + 2), 16);
			val[i] = (byte) j;
		}
		return val;

	}

	private static void receiveFileFromClient(String fileName , DataInputStream dis)
			throws Exception {
		int bytes = 0;
		FileOutputStream fileOutputStream = new FileOutputStream(fileName);

		long size = dis.readLong();
		byte[] buffer = new byte[8 * 1024];
		while (size > 0 && (bytes = dis.read(buffer, 0,(int) Math.min(buffer.length,size))) != -1) {
			
			fileOutputStream.write(buffer, 0, bytes);
			size -= bytes; 
		}
		
		//System.out.println("File is Received");
		fileOutputStream.close();
	}

}

// javac Server.java
// java Server 1234