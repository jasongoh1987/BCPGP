package com.fuzion.tools.pgp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

/**
 * Bouncy castle OpenPGP utilities
 * 
 * @author B49879
 *
 */
public abstract class BCPGPUtils {

	/**
	 * 
	 * Read public key from public key input stream, if there is more than 1
	 * public key in the files, the first 1 will be returned
	 * 
	 * @param publicKeyInputStream
	 *            Public key InputStream
	 * @return PGPublicKey instance, or null if there is no key found
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPPublicKey readPublicKey(InputStream publicKeyInputStream) throws IOException, PGPException {

		InputStream in = PGPUtil.getDecoderStream(publicKeyInputStream);
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);//, new BcKeyFingerprintCalculator());
		PGPPublicKey key = null;

		Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
		while (key == null && rIt.hasNext()) {
			PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
			Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();

			while (key == null && kIt.hasNext()) {
				PGPPublicKey k = (PGPPublicKey) kIt.next();
				if (k.isEncryptionKey()) {
					key = k;
				}
			}
		}

		if (key == null) {
			throw new IllegalArgumentException("Can't find encryption key in key ring.");
		}
		in.close();
		publicKeyInputStream.close();
		return key;
	}

	/**
	 * 
	 * Read public key from public key file, if there is more than 1 public key
	 * in the files, the first 1 will be returned
	 * 
	 * @param publicKeyFilePath
	 *            Public key file path
	 * @return PGPublicKey instance, or null if there is no key found
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPPublicKey readPublicKeyFromFile(String publicKeyFilePath) throws IOException, PGPException {

		InputStream fin = new FileInputStream(new File(publicKeyFilePath));
		return BCPGPUtils.readPublicKey(fin);
	}

	/**
	 * 
	 * Read public key from public key string, if there is more than 1 public
	 * key in the string, the first 1 will be returned
	 * 
	 * @param publicKeyString
	 *            Public key string
	 * @return PGPublicKey instance, or null if there is no key found
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPPublicKey readPublicKeyFromString(String publicKeyString) throws IOException, PGPException {
		InputStream sin = new ByteArrayInputStream(publicKeyString.getBytes(StandardCharsets.UTF_8));
		return BCPGPUtils.readPublicKey(sin);
	}

	/**
	 * 
	 * Read public key from public key file for the matching key ID
	 * 
	 * @param publicKeyFileInputStream
	 *            Public key InputStream
	 * @param keyId
	 *            Matching key ID
	 * @return PGPublicKey instance, or null if there is no key found
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPPublicKey readPublicKey(InputStream publicKeyFileInputStream, long keyId)
			throws IOException, PGPException {
		InputStream in = PGPUtil.getDecoderStream(publicKeyFileInputStream);
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);//, new BcKeyFingerprintCalculator());
		PGPPublicKey key = null;

		Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
		while (rIt.hasNext()) {
			PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
			Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();

			while (kIt.hasNext()) {
				PGPPublicKey k = (PGPPublicKey) kIt.next();
				long keyid = k.getKeyID();
				if (keyid == keyId) {
					key = k;
				}
			}
		}

		in.close();
		publicKeyFileInputStream.close();

		if (key == null) {
			throw new IllegalArgumentException("Can't find encryption key in key ring.");
		}

		return key;
	}

	/**
	 * 
	 * Read public key from public key file for the matching key ID
	 * 
	 * @param publicKeyFilePath
	 *            Public key file path
	 * @param keyId
	 *            Matching key ID
	 * @return PGPublicKey instance, or null if there is no key found
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPPublicKey readPublicKeyFromFile(String publicKeyFilePath, long keyId)
			throws IOException, PGPException {
		InputStream fin = new FileInputStream(new File(publicKeyFilePath));
		return BCPGPUtils.readPublicKey(fin, keyId);
	}

	/**
	 * 
	 * Read public key from public key file for the matching key ID
	 * 
	 * @param publicKeyString
	 *            Public key file path
	 * @param keyId
	 *            Matching key ID
	 * @return PGPublicKey instance, or null if there is no key found
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPPublicKey readPublicKeyFromString(String publicKeyString, long keyId)
			throws IOException, PGPException {
		InputStream sin = new ByteArrayInputStream(publicKeyString.getBytes(StandardCharsets.UTF_8));
		return BCPGPUtils.readPublicKey(sin, keyId);
	}

	/**
	 * 
	 * Read private key from InputStream for matching key ID
	 * 
	 * @param privateKeyInputStream
	 *            Private key input stream
	 * @param keyID
	 *            Matching Key ID
	 * @param pass
	 *            Password to open private key
	 * @return PGPPrivateKey instance or null if not found
	 * @throws IOException
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 */
	public static PGPPrivateKey findPrivateKey(InputStream privateKeyInputStream, long keyID, char[] pass)
			throws IOException, PGPException, NoSuchProviderException {
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
				PGPUtil.getDecoderStream(privateKeyInputStream));//, new BcKeyFingerprintCalculator());

		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey == null) {
			return null;
		}
		PGPDigestCalculatorProvider digCalPro = new BcPGPDigestCalculatorProvider();
		PBESecretKeyDecryptor dec = new BcPBESecretKeyDecryptorBuilder(digCalPro).build(pass);
		return pgpSecKey.extractPrivateKey(dec);
	}

	/**
	 * Read secret key from InputStream, if there is more than 1 public key in
	 * the files, the first 1 will be returned
	 * 
	 * @param secretKeyInputStream
	 *            Secret key input stream
	 * @return PGPSecretKey instance or null if not found
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPSecretKey findSecretKey(InputStream secretKeyInputStream) throws IOException, PGPException {
		InputStream decodedSecretKeyInputStream = PGPUtil.getDecoderStream(secretKeyInputStream);
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(decodedSecretKeyInputStream);//new BcKeyFingerprintCalculator());

		PGPSecretKey key = null;

		// iterate through the key rings.
		Iterator<PGPSecretKeyRing> rIt = pgpSec.getKeyRings();

		while (key == null && rIt.hasNext()) {
			PGPSecretKeyRing kRing = (PGPSecretKeyRing) rIt.next();
			Iterator<PGPSecretKey> kIt = kRing.getSecretKeys();

			while (key == null && kIt.hasNext()) {
				PGPSecretKey k = (PGPSecretKey) kIt.next();

				if (k.isSigningKey()) {
					key = k;
				}
			}
		}

		decodedSecretKeyInputStream.close();
		secretKeyInputStream.close();
		
		if (key == null) {
			throw new IllegalArgumentException("Can't find signing key in key ring.");
		}
		return key;
	}
}
