package com.fuzion.tools.pgp.command;

import java.io.Console;
import java.io.File;
import java.security.Security;

import com.fuzion.tools.pgp.BCPGPDecryptor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DecryptCommand {
	private static final String privateKeyPath = "keys/sec.key";
	private static final String publicKeyPath = "keys/hlb_pub.key";


	public static void main(String[] args) throws Exception {

		Security.addProvider(new BouncyCastleProvider());
		
		File privateKeyFile = new File(privateKeyPath);
		if (!privateKeyFile.exists()) {
			System.out.println("Please ensure the secret key file 'sec.key' exists in the same directory.");
			return;
		}	
		
		File publicKeyFile = new File(publicKeyPath);
		if (!publicKeyFile.exists()) {
			System.out.println("Please ensure the public key file 'hlb_pub.key' exists in the same directory.");
			return;
		}	
		
		Console console = System.console();
		console.printf("Please enter file path for decryption : ");
		String filename = console.readLine();
		
		File file = new File(filename);
		while (!file.exists()) {
			console.printf("Invalid file path. Please enter a valid file path for decryption : ");
			filename = console.readLine();
			file = new File(filename);
		}
		
		console.printf("Please enter the password for the secret key : ");
		char[] passwordChars = console.readPassword();
		String passwordString = new String(passwordChars);
		boolean fileExistBeforeDecrypt = false;
		File decryptedFile = null;
		
		// decrypt file
		try {
			BCPGPDecryptor decryptor = new BCPGPDecryptor();
			decryptor.setPrivateKeyFilePath(privateKeyPath);
			decryptor.setPassword(passwordString);
			decryptor.setSigned(true);
			String originalName = file.getName();
			String decryptFileName;
			if(originalName.endsWith(".enc"))
				decryptFileName = originalName.substring(0, originalName.length()-4);
			else
				decryptFileName = originalName + ".dec";
			decryptedFile = new File(decryptFileName);
			fileExistBeforeDecrypt = decryptedFile.exists();
			
			decryptor.setSigningPublicKeyFilePath(publicKeyPath);
			decryptor.decryptFile(file, decryptedFile);
			
			System.out.println("");
			System.out.println("File has been decrypted successfully.");
			System.out.println("Input File : " + file);
			System.out.println("Decrypted File : " + decryptedFile);
			System.out.println("");
			
		} catch (Exception e) {
			System.out.println("Failed to decrypt file. [" + e.toString() + "]");
			
			// If decrypt file not exist before decrypt, then clean up
			if(!fileExistBeforeDecrypt){
				if(decryptedFile != null && decryptedFile.exists()){
					decryptedFile.delete();
				}
			}
		}
		
	}
}
