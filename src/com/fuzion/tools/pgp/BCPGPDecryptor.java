package com.fuzion.tools.pgp;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.CharSequenceInputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

import com.sun.xml.internal.messaging.saaj.util.ByteInputStream;

/**
 * Bounty castle PGP decryptor
 * 
 * @author B49879
 *
 */
public class BCPGPDecryptor {

	private String privateKeyFilePath;
	private String password = "";
	private byte[] signingPublicKey;
    private byte[] privateKey;

	private boolean isSigned;

	/**
	 * Is checking signature
	 * 
	 * @return true if checking signature is required, false otherwise
	 */
	public boolean isSigned() {
		return isSigned;
	}

	/**
	 * Set to check signature
	 * 
	 * @param isSigned
	 *            true to check signature, false to not check
	 */
	public void setSigned(boolean isSigned) {
		this.isSigned = isSigned;
	}

	/**
	 * Set signing public key file path
	 * 
	 * @param signingPublicKeyFilePath
	 *            Signing public key file path
	 * @throws IOException
	 */
	public void setSigningPublicKeyFilePath(String signingPublicKeyFilePath) throws IOException {
		InputStream fin = new FileInputStream(new File(signingPublicKeyFilePath));
		signingPublicKey = IOUtils.toByteArray(fin);
		IOUtils.closeQuietly(fin);
	}

    /**
     * Set private key
     *
     * @param privateKeyString private key string
     * @throws IOException
     */
    public void setPrivateKey(String privateKeyString) throws IOException {
        InputStream keyIn = new ByteArrayInputStream(privateKeyString.getBytes(StandardCharsets.UTF_8));
        privateKey = IOUtils.toByteArray(keyIn);
        IOUtils.closeQuietly(keyIn);
    }

	/**
	 * Set signing public key string
	 * 
	 * @param signingPublicKeyString
	 *            Signing public key string
	 * @throws IOException
	 */
	public void setSigningPublicKeyString(String signingPublicKeyString) throws IOException {
		InputStream sin = new ByteArrayInputStream(signingPublicKeyString.getBytes(StandardCharsets.UTF_8));
		signingPublicKey = IOUtils.toByteArray(sin);
		IOUtils.closeQuietly(sin);
	}

	/**
	 * Get private key file path
	 * 
	 * @return Private key file path
	 */
	public String getPrivateKeyFilePath() {
		return privateKeyFilePath;
	}

	/**
	 * Set private key file path
	 * 
	 * @param privateKeyFilePath
	 *            Private key file path
	 */
	public void setPrivateKeyFilePath(String privateKeyFilePath) throws IOException {
        this.privateKeyFilePath = privateKeyFilePath;
        InputStream keyIn = null;
        try {
            keyIn = new FileInputStream(new File(privateKeyFilePath));
            privateKey = IOUtils.toByteArray(keyIn);
        }
        catch(Exception e){
            throw e;
        }
        finally {
            IOUtils.closeQuietly(keyIn);
        }
    }

	/**
	 * Get password to open private key
	 * 
	 * @return Password to open private key
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * Set password to open private key
	 * 
	 * @param password
	 *            Password to open private key
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * Decrypt file
	 * 
	 * @param inputFileNamePath
	 *            Input file path
	 * @param outputFileNamePath
	 *            Output file path
	 * @throws Exception
	 */
	public void decryptFile(String inputFileNamePath, String outputFileNamePath) throws Exception {
		File in = null;
		File out = null;
		try {
			in = new File(inputFileNamePath);
			out = new File(outputFileNamePath);
			decryptFile(in, out);
		} catch (Exception e) {
			out.delete();
			throw (e);
		}
	}

	/**
	 * Decrypt file
	 * 
	 * @param inputFile
	 *            Input file
	 * @param outputFile
	 *            Output file
	 * @throws Exception
	 */
	public void decryptFile(File inputFile, File outputFile) throws Exception {
		decrypt(new FileInputStream(inputFile), new FileOutputStream(outputFile));
	}

	/**
	 * Decrypt file
	 * 
	 * @param inputFileNamePath
	 *            Input file path
	 * @return Decrypted message
	 * @throws Exception
	 */
	public String decryptFile(String inputFileNamePath) throws Exception {
		return decryptFile(new File(inputFileNamePath));
	}

	/**
	 * Decrypt file
	 * 
	 * @param inputFile
	 *            Input file
	 * @return Decrypted message
	 * @throws Exception
	 */
	public String decryptFile(File inputFile) throws Exception {
		String value = null;
		ByteArrayOutputStream out = null;
		InputStream in = null;
		try {
			out = new ByteArrayOutputStream();
			in = new FileInputStream(inputFile);
			decrypt(in, out);
			value = out.toString(Charsets.UTF_8.name());
		} finally {
			IOUtils.closeQuietly(in);
			IOUtils.closeQuietly(out);
		}
		return value;
	}

	/**
	 * Decrypt
	 * 
	 * @param in
	 *            Input stream for ciphertext
	 * @param out
	 *            Output stream for plaintext
	 * @throws Exception
	 */
	public void decrypt(InputStream in, OutputStream out) throws Exception {
		InputStream unc = null;
		BufferedOutputStream bOut = null;
		try {
			bOut = new BufferedOutputStream(out);
			unc = decrypt(in);
			byte[] bytes = IOUtils.toByteArray(unc);
			bOut.write(bytes);
			bOut.flush();
		} finally {
			IOUtils.closeQuietly(bOut);
			IOUtils.closeQuietly(unc);
			IOUtils.closeQuietly(in);
			IOUtils.closeQuietly(out);
		}
	}

	/**
	 * Decrypt
	 * 
	 * @param cipherIn Input stream for ciphertext
	 * @return Input stream for plain text
	 * @throws Exception
	 */
	public InputStream decrypt(InputStream cipherIn) throws Exception {
		byte[] bytes = null;
		InputStream is = null;
		InputStream keyIn = null;
		InputStream decodedFileIn = null;
		InputStream clear = null;
		InputStream decodedSigningPublicKey = null;

		try {
            keyIn = new ByteInputStream(privateKey, privateKey.length);

			char[] passwd = password.toCharArray();
			decodedFileIn = PGPUtil.getDecoderStream(cipherIn);

			PGPObjectFactory pgpF = new PGPObjectFactory(decodedFileIn, new BcKeyFingerprintCalculator());
			PGPEncryptedDataList enc;
			Object o = pgpF.nextObject();

			// the first object might be a PGP marker packet.
			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();
			}

            if( enc == null ){
                throw new PGPException("Please select a valid file for decryption.");
            }

			// find the secret key
			Iterator<?> it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;
			while (sKey == null && it.hasNext()) {
				pbe = (PGPPublicKeyEncryptedData) it.next();
				sKey = BCPGPUtils.findPrivateKey(keyIn, pbe.getKeyID(), passwd);
			}

			if (sKey == null) {
//				throw new IllegalArgumentException("secret key for message not found.");
                throw new IllegalArgumentException("Please select a valid file for decryption.");
			}

			clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
			PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());
			Object message = plainFact.nextObject();

			PGPObjectFactory pgpFact = null;
			if (message instanceof PGPCompressedData) {
				PGPCompressedData cData = (PGPCompressedData) message;
				pgpFact = new PGPObjectFactory(cData.getDataStream(), new BcKeyFingerprintCalculator());
				message = pgpFact.nextObject();
			}

			PGPOnePassSignature ops = null;
			if (message instanceof PGPOnePassSignatureList) {
				if (isSigned) {
					PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;
					ops = p1.get(0);
					long keyId = ops.getKeyID();
					ByteInputStream bin = new ByteInputStream(signingPublicKey, signingPublicKey.length);
					decodedSigningPublicKey = PGPUtil.getDecoderStream(bin);
					PGPPublicKey signerPublicKey = BCPGPUtils.readPublicKey(decodedSigningPublicKey, keyId);
					ops.init(new BcPGPContentVerifierBuilderProvider(), signerPublicKey);
				}
				if(pgpFact != null){
					message = pgpFact.nextObject();
				}
				else{
					message = plainFact.nextObject();
				}
			}

			if (message instanceof PGPLiteralData) {
				PGPLiteralData ld = (PGPLiteralData) message;
				is = ld.getInputStream();
				bytes = IOUtils.toByteArray(is);

				if (pbe.isIntegrityProtected()) {
					if (!pbe.verify()) {
						throw new PGPException("File failed integrity check");
					}
				}

				if (isSigned) {
					ops.update(bytes);
					PGPSignatureList p3 = null;
					try {
						if(pgpFact != null){
							p3 = (PGPSignatureList) pgpFact.nextObject();
						}
						else{
							p3 = (PGPSignatureList) plainFact.nextObject();
						}
						
					} catch (EOFException e) { // no signature found
					}
					if (p3 != null && !ops.verify(p3.get(0))) {
						throw new PGPException("Signature verification failed!");
					}

				}
			} else {
				throw new PGPException("Please select a valid file for decryption.");
			}
		} finally {
			IOUtils.closeQuietly(is);
			IOUtils.closeQuietly(keyIn);
			IOUtils.closeQuietly(decodedFileIn);
			IOUtils.closeQuietly(clear);
			IOUtils.closeQuietly(decodedSigningPublicKey);
			IOUtils.closeQuietly(cipherIn);
		}
		return new ByteArrayInputStream(bytes);
	}

}