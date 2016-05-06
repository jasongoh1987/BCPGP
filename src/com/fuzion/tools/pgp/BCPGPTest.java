package com.fuzion.tools.pgp;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;

public class BCPGPTest {
	private static final String pubKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v2\n\nmQENBFZEblcBCACUBouu9kV0M3JOI2KfVSWJvdg7JTBBYZWNXsE5Z9hSPwSw72Wn\njKDmYTOg287T1HH9VXJAOUIBdHADwtAFkeHcYBiIKyjIvkN69nVrjxHT3LiS7AD9\n9PvFJa8JXnhfNHK4BG66BPxzOc37eT9bAErbMxuIsVTo1w7qa0DOEK4OBzf2EDsL\nqf2z4+lxMoqUz/MS/FQiA8PVV+u///vjaST3l0cNUxQe4pu5uYTBeUFAZSh1FusL\nGTuzhm71KDf9Jfom6rzOQi7ErpdKWAtKR3YsvKElinPQUMSVs8BCAbJ9ln2+vfQH\ngptpMwEy3hcU9/j5OfZjW13iWd2uQAtHt32DABEBAAG0L2phc29uICh0ZXN0KSA8\namFzb25nb2hoeEBobGJiLmhvbmdsZW9uZy5jb20ubXk+iQE5BBMBCAAjBQJWRG5X\nAhsDBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQu38poUfac7XoOwf/aEbU\nZag+T5ik4dtn4svhGA/Cq4Xb1EH/27FsjJ9eXQ+wmBKnZ0KPSOXsuV90xFbVxyww\n1XChyKEKC0ard5cTM0arBaDTAro1df3EeI3Yttmofsw/+L+7RntlODxHdJ8Jts3Z\nve1FMw4EcDMLV6JaNi0REXbyGw7jTiXbZSGiehk2eu5InQybOwutDBUMJ9a0dsla\nQWqwUxyiB39I2bfoGnOob3xK7dT4PdAXC9IAFaLkJOj6QET7FpBzfiMRYjuddj8a\nTj57Ufx3A79YUp3ul4kaKbyMRni+Z5UvKtWGdgGuG2odi9MDjWDnLyELLiPUa2W4\nvB9KqI7Y4KIbTQoZDLkBDQRWRG5XAQgArju5s+rmYR/go34JiwOvVqdRxoVLU/xZ\ndxNHUZYAkSNizdEqAwfJoFAqAaboABYnUyMnuS+tUebx9Z7W2cxKnJhyCtiyVglL\n0E8fw4a2a/x5EkyXDl/QMt5FklE+TVI0R8uQMSAZizZv81UoudrdCxYYKEKtKiUO\noD4mqa9TioRcqtM8nZ02GFB9VhvviXvHB1UFnEDdO0v5j8lK1VaWrCc3aNj/kBld\nt/6e6YDeaUHosCu1dg4uDiQbGWS4DLj3q1LBrJlacbyrsZQNf3LrsxtjwINnYv+n\n75uu1UWi488LVfeGJytJskM5UMyPnhSQ/zwKNbBigwuyJXy+SVzC9wARAQABiQEf\nBBgBCAAJBQJWRG5XAhsMAAoJELt/KaFH2nO1h7sH/2A1dIkFYJuzeQp3U7cfxaUi\n8sHvPu9A7Y05KqtyET5aQeSRL+vrtfN9IblHylpI/jkGicEan7RfIIABicdpdc+R\nhh0nbl8rJbHy5m5bphJsjSrgJARcmWoWhBY3MdpF+G2WcomoRsougno3UOCgY1FX\nyRqk0YjdAhDfjX3HHIT4a/7/YNTTI9QbJzzkG49cuX7gQCd9C7ZJcnlBaPq10Zbw\nd0TItwrQ74sQAr/bIdXBQNsrltqD9jDM5mccLd2iOltijxR/DZzEi7j2zYnZLXCc\nTNxf6QOnfoibvWrnDJvFlgTpJE17LLxwCEGR0wJxQOZVX9AZFoJmPZ2MK89pCbI=\n=WCvz\n-----END PGP PUBLIC KEY BLOCK-----\n";

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		encryptFile();
		decryptFile();
		encryptAndSignFile();
		decryptSignedFile();
		decryptSignedFile1();
		decryptSignedFileWithoutSignatureVerification();
		encryptAndSignFileHLB();
		decryptSignedFileHLB();
	}

	public static void encryptFile() throws Exception {
		BCPGPEncryptor encryptor = new BCPGPEncryptor();
		encryptor.setArmored(true);
		encryptor.setCheckIntegrity(true);
		// encryptor.setPublicKeyFilePath("./public.key");
		// encryptor.setPublicKeyFilePath("./test.gpg.pub");
		encryptor.setPublicKeyString(pubKey);
		encryptor.encryptFile("./test.txt", "./test.txt.enc");
	}

	public static void decryptFile() throws Exception {
		BCPGPDecryptor decryptor = new BCPGPDecryptor();
		// decryptor.setPrivateKeyFilePath("test.gpg.prv");
		decryptor.setPrivateKeyFilePath("secret.key");
		decryptor.setPassword("Hlb!1234");
		// decryptor.decryptFile("test.txt.enc", "test.txt.dec");
		System.out.println(decryptor.decryptFile("test.txt.enc"));
	}

	public static void encryptAndSignFile() throws Exception {
		BCPGPEncryptor encryptor = new BCPGPEncryptor();
		encryptor.setArmored(true);
		encryptor.setCheckIntegrity(true);
		encryptor.setPublicKeyFilePath("./test.gpg.pub");
		encryptor.setSigning(true);
		// encryptor.setSigningPrivateKeyFilePath("wahaha.gpg.prv");
		// encryptor.setSigningPrivateKeyPassword("password");
		encryptor.setSigningPrivateKeyFilePath("secret.key");
		encryptor.setSigningPrivateKeyPassword("Hlb!1234");

		encryptor.encryptFile("./test.txt", "./test.txt.signed.enc");
	}
	
	public static void encryptAndSignFileHLB() throws Exception {
		BCPGPEncryptor encryptor = new BCPGPEncryptor();
		encryptor.setArmored(true);
		encryptor.setCheckIntegrity(true);
		encryptor.setPublicKeyFilePath("./bin/keys/hlb_pub.key");
		encryptor.setSigning(true);
		encryptor.setSigningPrivateKeyFilePath("./bin/keys/sec.key");
		encryptor.setSigningPrivateKeyPassword("jason");

		encryptor.encryptFile("./test.txt", "./test2.txt.signed.enc");
	}

	public static void decryptSignedFileHLB() throws Exception {
		BCPGPDecryptor decryptor = new BCPGPDecryptor();
		decryptor.setPrivateKeyFilePath("./bin/keys/hlb_sec.key");
		decryptor.setPassword("Hlb!1234");
		decryptor.setSigned(true);
		decryptor.setSigningPublicKeyFilePath("./bin/keys/pub.key");

		System.out.println(decryptor.decryptFile("test2.txt.signed.enc"));
	}
	
	public static void decryptSignedFile() throws Exception {
		BCPGPDecryptor decryptor = new BCPGPDecryptor();
		decryptor.setPrivateKeyFilePath("test.gpg.prv");
		decryptor.setPassword("password");
		decryptor.setSigned(true);
		// decryptor.setSigningPublicKeyFilePath("wahaha.gpg.pub");
		// decryptor.setSigningPublicKeyFilePath("public.key");
		decryptor.setSigningPublicKeyString(pubKey);

		// this file is encrypted with weili's public key and signed using
		// wahaha's private key
		// decryptor.decryptFile("test.txt.signed.enc", "test.txt.signed.dec");
		System.out.println(decryptor.decryptFile("test.txt.signed.enc"));
	}

	public static void decryptSignedFile1() throws Exception {
		BCPGPDecryptor decryptor = new BCPGPDecryptor();
		decryptor.setPrivateKeyFilePath("test.gpg.prv");
		decryptor.setPassword("password");
		decryptor.setSigned(true);
		decryptor.setSigningPublicKeyFilePath("wahaha.gpg.pub");

		// this file is encrypted with weili's public key and signed using
		// wahaha's private key
		// decryptor.decryptFile("test.txt.signed.asc", "test.txt.signed.dec1");
		System.out.println(decryptor.decryptFile("test.txt.signed.asc"));
	}

	public static void decryptSignedFileWithoutSignatureVerification() throws Exception {
		BCPGPDecryptor decryptor = new BCPGPDecryptor();
		decryptor.setPrivateKeyFilePath("test.gpg.prv");
		decryptor.setPassword("password");

		// this file is encrypted with weili's public key and signed using
		// wahaha's private key
		// decryptor.decryptFile("test.txt.signed.asc", "test.txt.signed.dec2");
		System.out.println(decryptor.decryptFile("test.txt.signed.asc"));
	}
}