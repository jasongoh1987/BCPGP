package com.fuzion.tools.pgp.command;

import java.io.Console;
import java.io.File;
import java.security.KeyPair;

import com.fuzion.tools.pgp.BCPGPKeyGenTools;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;

public class KeyGenerationCommand {

	public static void main(String[] args) {
		try {
			String keysDir = System.getProperty("user.dir") + File.separator + "keys";

			File keysDirFile = new File(keysDir);
			if(!keysDirFile.exists()) {
				keysDirFile.mkdirs();
			}

			String identity;
			String password;

			if(args.length == 2) {
				// console mode
				identity= args[0];
				password = args[1];            	

			} else {
				Console console = System.console();
				console.printf("Please enter a name for the key pair : ");

				// command mode
				identity = console.readLine();

				char[] passwordChars = null;
				while (passwordChars == null) {
					console.printf("Please enter a password the secret key : ");
					passwordChars = console.readPassword();
				}

				password = new String(passwordChars);
			}

			KeyPair rsaSignKeyPair = BCPGPKeyGenTools.generateRsaKeyPair(2048);
			KeyPair rsaEncryptKeyPair = BCPGPKeyGenTools.generateRsaKeyPair(2048);

			PGPKeyRingGenerator pgpKeyRingGen = BCPGPKeyGenTools.createPGPKeyRingGeneratorForRSAKeyPair(
					rsaSignKeyPair,
					rsaEncryptKeyPair,
					identity,
					password.toCharArray()
					);

			File secKeyFile = new File(keysDir + File.separator + "sec.key");
			File pubKeyFile = new File(keysDir + File.separator + "pub.key");
			
			BCPGPKeyGenTools.exportSecretKey(pgpKeyRingGen, secKeyFile, true);
			BCPGPKeyGenTools.exportPublicKey(pgpKeyRingGen, pubKeyFile, true);
			
			System.out.println("");
			System.out.println("Keys have been generated successfully.");
			System.out.println("Public Key : " + pubKeyFile);
			System.out.println("Secret Key : " + secKeyFile);
			System.out.println("");

		} catch(Exception e) {
			System.out.println("Failed to generate key pair. [" + e.toString() + "]");
		}
	}
}