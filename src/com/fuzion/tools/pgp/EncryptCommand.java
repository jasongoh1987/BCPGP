package com.fuzion.tools.pgp;

import java.io.Console;
import java.io.File;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EncryptCommand {
	private static final String pubKeyPath = "keys/hlb_pub.key";
	private static final String privateKeyPath = "keys/sec.key";

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		
		File pubKeyFile = new File(pubKeyPath);
		if (!pubKeyFile.exists()) {
			System.out.println("Please ensure the public key file 'hlb_pub.key' exists in the same directory.");
			return;
		}
		
		File privateKeyFile = new File(privateKeyPath);
		if (!privateKeyFile.exists()) {
			System.out.println("Please ensure the private key file 'sec.key' exists in the same directory.");
			return;
		}
		
		Console console = System.console();
		console.printf("Please enter file path for encryption : ");
		String filename = console.readLine();
		
		File file = new File(filename);
		while (!file.exists()) {
			console.printf("Invalid file path. Please enter a valid file path for encryption : ");
			filename = console.readLine();
			file = new File(filename);
		}
		
		// encrypt file
		try {
			File encryptedFile = new File(filename + ".enc");
			
			BCPGPEncryptor encryptor = new BCPGPEncryptor();
			encryptor.setArmored(true);
			encryptor.setCheckIntegrity(true);
			encryptor.setPublicKeyFilePath(pubKeyPath);
			encryptor.setSigning(true);
			encryptor.setSigningPrivateKeyFilePath(privateKeyPath);
			
			console.printf("Please enter signing private key password: ");
			char[] privateKeyPass = console.readPassword();
			encryptor.setSigningPrivateKeyPassword(new String(privateKeyPass));
			encryptor.encryptFile(file, encryptedFile);
			
			System.out.println("");
			System.out.println("File has been encrypted successfully.");
			System.out.println("Input File : " + file);
			System.out.println("Encrypted File : " + encryptedFile);
			System.out.println("");
			
		} catch (Exception e) {
			System.out.println("Failed to encrypt file. [" + e.toString() + "]");
		}
	}

}
