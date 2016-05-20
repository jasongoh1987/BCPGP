package com.fuzion.tools.pgp;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Iterator;

import com.sun.xml.internal.messaging.saaj.util.ByteInputStream;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

/**
 * Bounty castle PGP encryptor
 * 
 * @author B49879
 *
 */
public class BCPGPEncryptor {

	private boolean isArmored;
	private boolean checkIntegrity;
	private boolean isSigning;
	private int messageDigestAlgorithm;
	private int signatureDocumentType;
	private char literalDataFormat;
	private int literalDataCompressionFormat;
	private int literalDataEncryptingAlgorithm;
	private PGPPublicKey publicKey;
	private String signingPrivateKeyFilePath;
	private String signingPrivateKeyPassword;
    private byte[] signingPrivateKey;

	public BCPGPEncryptor() {
		messageDigestAlgorithm = PGPUtil.SHA1;
		signatureDocumentType = PGPSignature.BINARY_DOCUMENT;
		literalDataFormat = PGPLiteralData.BINARY;
		literalDataEncryptingAlgorithm = PGPEncryptedData.AES_256;
		literalDataCompressionFormat = PGPCompressedData.ZIP;
	}

	/**
	 * Get signing private key password
	 * 
	 * @return signing private key password
	 */
	public String getSigningPrivateKeyPassword() {
		return signingPrivateKeyPassword;
	}

	/**
	 * Set signing private key password
	 * 
	 * @param signingPrivateKeyPassword
	 *            Signing private key password
	 */
	public void setSigningPrivateKeyPassword(String signingPrivateKeyPassword) {
		this.signingPrivateKeyPassword = signingPrivateKeyPassword;
	}

    /**
     * Set signing private key string
     *
     * @param signingPrivateKeyString
     *            Signing private key string
     * @throws IOException
     */
    public void setSigningPrivateKeyString(String signingPrivateKeyString) throws IOException {
        InputStream sin = new ByteArrayInputStream(signingPrivateKeyString.getBytes(StandardCharsets.UTF_8));
        signingPrivateKey = IOUtils.toByteArray(sin);
        IOUtils.closeQuietly(sin);
    }

	/**
	 * Get signing private key file path
	 * 
	 * @return signing private key file path
	 */
	public String getSigningPrivateKeyFilePath() {
		return signingPrivateKeyFilePath;
	}

    /**
     * Set signing private key file path
     *
     * @param signingPrivateKeyFilePath signing private key file path
     * @throws IOException
     */
	public void setSigningPrivateKeyFilePath(String signingPrivateKeyFilePath) throws IOException {
		this.signingPrivateKeyFilePath = signingPrivateKeyFilePath;
        InputStream keyInputStream = new FileInputStream(new File(signingPrivateKeyFilePath));
        signingPrivateKey = IOUtils.toByteArray(keyInputStream);
        IOUtils.closeQuietly(keyInputStream);
	}

	/**
	 * Is encryptor signing a certificate
	 * 
	 * @return true if encryptor is signing a certificate, false otherwise
	 */
	public boolean isSigning() {
		return isSigning;
	}

	/**
	 * Set encryptor to sign certificate
	 * 
	 * @param isSigning
	 *            true to sign certificate, false to not sign certificate
	 */
	public void setSigning(boolean isSigning) {
		this.isSigning = isSigning;
	}

	/**
	 * Set public key file path
	 * 
	 * @param publicKeyFilePath
	 *            Public key file path
	 * @throws IOException
	 * @throws PGPException
	 */
	public void setPublicKeyFilePath(String publicKeyFilePath) throws IOException, PGPException {
		publicKey = BCPGPUtils.readPublicKeyFromFile(publicKeyFilePath);
	}

	/**
	 * Set public key string
	 * 
	 * @param publicKeyString
	 *            Public key string
	 * @throws IOException
	 * @throws PGPException
	 */
	public void setPublicKeyString(String publicKeyString) throws IOException, PGPException {
		publicKey = BCPGPUtils.readPublicKeyFromString(publicKeyString);
	}

	/**
	 * Is encryptor using armored file output stream
	 * 
	 * @return true if encryptor is using armored file output stream, false
	 *         otherwise
	 */
	public boolean isArmored() {
		return isArmored;
	}

	/**
	 * Set encryptor to use armored file output stream
	 * 
	 * @param isArmored
	 *            true to use armored file output stream, false to not use
	 */
	public void setArmored(boolean isArmored) {
		this.isArmored = isArmored;
	}

	/**
	 * Is encryptor set integrity check
	 * 
	 * @return true if encryptor has integrity check
	 */
	public boolean isCheckIntegrity() {
		return checkIntegrity;
	}

	/**
	 * Set encryptor to send integrity check packet
	 * 
	 * @param checkIntegrity
	 *            true to send integrity check packet, false to not send
	 */
	public void setCheckIntegrity(boolean checkIntegrity) {
		this.checkIntegrity = checkIntegrity;
	}

	/**
	 * Get message digest algorithm
	 * 
	 * @return Message digest algorithm
	 */
	public int getMessageDigestAlgorithm() {
		return messageDigestAlgorithm;
	}

	/**
	 * Set message digest algorithm
	 * 
	 * @param messageDigestAlgorithm
	 *            Message digest algorithm
	 */
	public void setMessageDigestAlgorithm(int messageDigestAlgorithm) {
		this.messageDigestAlgorithm = messageDigestAlgorithm;
	}

	/**
	 * Get signature document type
	 * 
	 * @return Signature document type
	 */
	public int getSignatureDocumentType() {
		return signatureDocumentType;
	}

	/**
	 * Set signature document type
	 * 
	 * @param signatureDocumentType
	 *            Signature document type
	 */
	public void setSignatureDocumentType(int signatureDocumentType) {
		this.signatureDocumentType = signatureDocumentType;
	}

	/**
	 * Get literal data format
	 * 
	 * @return Literal data format
	 */
	public char getLiteralDataFormat() {
		return literalDataFormat;
	}

	/**
	 * Set literal data format
	 * 
	 * @param literalDataFormat
	 *            Literal data format
	 */
	public void setLiteralDataFormat(char literalDataFormat) {
		this.literalDataFormat = literalDataFormat;
	}

	/**
	 * Get literal data compression format
	 * 
	 * @return Literal data compression format
	 */
	public int getLiteralDataCompressionFormat() {
		return literalDataCompressionFormat;
	}

	/**
	 * Set literal data compression format
	 * 
	 * @param literalDataCompressionFormat
	 *            Literal data compression format
	 */
	public void setLiteralDataCompressionFormat(int literalDataCompressionFormat) {
		this.literalDataCompressionFormat = literalDataCompressionFormat;
	}

	/**
	 * Get literal data encrypting algorithm
	 * 
	 * @return Literal data encrypting algorithm
	 */
	public int getLiteralDataEncryptingAlgorithm() {
		return literalDataEncryptingAlgorithm;
	}

	/**
	 * Set literal data encrypting algorithm
	 * 
	 * @param literalDataEncryptingAlgorithm
	 *            Literal data encrypting algorithm
	 */
	public void setLiteralDataEncryptingAlgorithm(int literalDataEncryptingAlgorithm) {
		this.literalDataEncryptingAlgorithm = literalDataEncryptingAlgorithm;
	}

	/**
	 * Encrypt file
	 * 
	 * @param inputFileNamePath
	 *            Input file path
	 * @param outputFileNamePath
	 *            Output file path
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws PGPException
	 */
	public void encryptFile(String inputFileNamePath, String outputFileNamePath)
			throws IOException, SignatureException, NoSuchProviderException, PGPException {
		encryptFile(new File(inputFileNamePath), new File(outputFileNamePath));
	}

	/**
	 * Encrypt file
	 * 
	 * @param inputFile
	 *            Input file
	 * @param outputFile
	 *            Output file
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws PGPException
	 */
	public void encryptFile(File inputFile, File outputFile) throws IOException, SignatureException, NoSuchProviderException, PGPException {
		OutputStream literalDataOutStream = null;
		PGPLiteralDataGenerator lg = null;
		OutputStream fileOutStream = null;
		OutputStream armoredFileOutStream = null;
		OutputStream encryptOutStream = null;
		PGPCompressedDataGenerator comData = null;
		OutputStream compressedOutStream = null;
		InputStream fin = null;

		BcPGPDataEncryptorBuilder pgpDataEncryptorBuilder = new BcPGPDataEncryptorBuilder(
				literalDataEncryptingAlgorithm);
		// set one time session key
		pgpDataEncryptorBuilder.setSecureRandom(new SecureRandom());
		pgpDataEncryptorBuilder.setWithIntegrityPacket(checkIntegrity);
		PGPEncryptedDataGenerator pedg = new PGPEncryptedDataGenerator(pgpDataEncryptorBuilder);
		pedg.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));

		fileOutStream = new FileOutputStream(outputFile);
		if (isArmored) {
			armoredFileOutStream = new ArmoredOutputStream(fileOutStream);
			encryptOutStream = pedg.open(armoredFileOutStream, new byte[1 << 16]);
		} else {
			encryptOutStream = pedg.open(fileOutStream, new byte[1 << 16]);
		}

		comData = new PGPCompressedDataGenerator(literalDataCompressionFormat);
		compressedOutStream = comData.open(encryptOutStream);
		try {
			PGPSignatureGenerator sg = null;
			if (isSigning) {
				InputStream keyInputStream = new ByteInputStream(signingPrivateKey, signingPrivateKey.length);
				PGPSecretKey secretKey = BCPGPUtils.findSecretKey(keyInputStream);
				PGPDigestCalculatorProvider digCalPro = new BcPGPDigestCalculatorProvider();
				PBESecretKeyDecryptor dec = new BcPBESecretKeyDecryptorBuilder(digCalPro)
						.build(signingPrivateKeyPassword.toCharArray());
				PGPPrivateKey privateKey = secretKey.extractPrivateKey(dec);
				BcPGPContentSignerBuilder pgpContentSignerBuilder = new BcPGPContentSignerBuilder(
						secretKey.getPublicKey().getAlgorithm(), messageDigestAlgorithm);
				sg = new PGPSignatureGenerator(pgpContentSignerBuilder);

				sg.init(signatureDocumentType, privateKey);
				Iterator<?> it = secretKey.getPublicKey().getUserIDs();
				if (it.hasNext()) {
					PGPSignatureSubpacketGenerator ssg = new PGPSignatureSubpacketGenerator();
					String userID = (String) it.next();
					ssg.setSignerUserID(false, userID);
					sg.setHashedSubpackets(ssg.generate());
				}
				// write signature header
				sg.generateOnePassVersion(false).encode(compressedOutStream);
			}

			lg = new PGPLiteralDataGenerator();

			literalDataOutStream = lg.open(compressedOutStream, literalDataFormat, inputFile);

			fin = new FileInputStream(inputFile);
			byte[] bytes = IOUtils.toByteArray(fin);
			// Write encrypted message
			literalDataOutStream.write(bytes);
			literalDataOutStream.flush();

			if (isSigning) {
				sg.update(bytes);
				// write signature
				sg.generate().encode(compressedOutStream);
			}

		} catch (IOException e) {
			if (outputFile != null) {
				outputFile.delete();
			}
			throw (e);
		} catch (PGPException e) {
			if (outputFile != null) {
				outputFile.delete();
			}
			throw (e);
		} catch (SignatureException e) {
			if (outputFile != null) {
				outputFile.delete();
			}
			throw (e);
		} finally {
			IOUtils.closeQuietly(fin);
			IOUtils.closeQuietly(literalDataOutStream);
			if (lg != null) {
				lg.close();
			}
			IOUtils.closeQuietly(compressedOutStream);
			if (comData != null) {
				comData.close();
			}
			if (pedg != null) {
				pedg.close();
			}
			IOUtils.closeQuietly(armoredFileOutStream);
			IOUtils.closeQuietly(fileOutStream);
			IOUtils.closeQuietly(encryptOutStream);
		}
	}

}