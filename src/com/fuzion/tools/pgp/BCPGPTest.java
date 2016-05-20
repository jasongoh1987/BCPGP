package com.fuzion.tools.pgp;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BCPGPTest {
	private static final String pubKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v2\n\nmQENBFZEblcBCACUBouu9kV0M3JOI2KfVSWJvdg7JTBBYZWNXsE5Z9hSPwSw72Wn\njKDmYTOg287T1HH9VXJAOUIBdHADwtAFkeHcYBiIKyjIvkN69nVrjxHT3LiS7AD9\n9PvFJa8JXnhfNHK4BG66BPxzOc37eT9bAErbMxuIsVTo1w7qa0DOEK4OBzf2EDsL\nqf2z4+lxMoqUz/MS/FQiA8PVV+u///vjaST3l0cNUxQe4pu5uYTBeUFAZSh1FusL\nGTuzhm71KDf9Jfom6rzOQi7ErpdKWAtKR3YsvKElinPQUMSVs8BCAbJ9ln2+vfQH\ngptpMwEy3hcU9/j5OfZjW13iWd2uQAtHt32DABEBAAG0L2phc29uICh0ZXN0KSA8\namFzb25nb2hoeEBobGJiLmhvbmdsZW9uZy5jb20ubXk+iQE5BBMBCAAjBQJWRG5X\nAhsDBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQu38poUfac7XoOwf/aEbU\nZag+T5ik4dtn4svhGA/Cq4Xb1EH/27FsjJ9eXQ+wmBKnZ0KPSOXsuV90xFbVxyww\n1XChyKEKC0ard5cTM0arBaDTAro1df3EeI3Yttmofsw/+L+7RntlODxHdJ8Jts3Z\nve1FMw4EcDMLV6JaNi0REXbyGw7jTiXbZSGiehk2eu5InQybOwutDBUMJ9a0dsla\nQWqwUxyiB39I2bfoGnOob3xK7dT4PdAXC9IAFaLkJOj6QET7FpBzfiMRYjuddj8a\nTj57Ufx3A79YUp3ul4kaKbyMRni+Z5UvKtWGdgGuG2odi9MDjWDnLyELLiPUa2W4\nvB9KqI7Y4KIbTQoZDLkBDQRWRG5XAQgArju5s+rmYR/go34JiwOvVqdRxoVLU/xZ\ndxNHUZYAkSNizdEqAwfJoFAqAaboABYnUyMnuS+tUebx9Z7W2cxKnJhyCtiyVglL\n0E8fw4a2a/x5EkyXDl/QMt5FklE+TVI0R8uQMSAZizZv81UoudrdCxYYKEKtKiUO\noD4mqa9TioRcqtM8nZ02GFB9VhvviXvHB1UFnEDdO0v5j8lK1VaWrCc3aNj/kBld\nt/6e6YDeaUHosCu1dg4uDiQbGWS4DLj3q1LBrJlacbyrsZQNf3LrsxtjwINnYv+n\n75uu1UWi488LVfeGJytJskM5UMyPnhSQ/zwKNbBigwuyJXy+SVzC9wARAQABiQEf\nBBgBCAAJBQJWRG5XAhsMAAoJELt/KaFH2nO1h7sH/2A1dIkFYJuzeQp3U7cfxaUi\n8sHvPu9A7Y05KqtyET5aQeSRL+vrtfN9IblHylpI/jkGicEan7RfIIABicdpdc+R\nhh0nbl8rJbHy5m5bphJsjSrgJARcmWoWhBY3MdpF+G2WcomoRsougno3UOCgY1FX\nyRqk0YjdAhDfjX3HHIT4a/7/YNTTI9QbJzzkG49cuX7gQCd9C7ZJcnlBaPq10Zbw\nd0TItwrQ74sQAr/bIdXBQNsrltqD9jDM5mccLd2iOltijxR/DZzEi7j2zYnZLXCc\nTNxf6QOnfoibvWrnDJvFlgTpJE17LLxwCEGR0wJxQOZVX9AZFoJmPZ2MK89pCbI=\n=WCvz\n-----END PGP PUBLIC KEY BLOCK-----\n";
    private static final String hlbSecKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                                            "Version: GnuPG v2\n" +
                                            "\n" +
                                            "lQO+BFZEblcBCACUBouu9kV0M3JOI2KfVSWJvdg7JTBBYZWNXsE5Z9hSPwSw72Wn\n" +
                                            "jKDmYTOg287T1HH9VXJAOUIBdHADwtAFkeHcYBiIKyjIvkN69nVrjxHT3LiS7AD9\n" +
                                            "9PvFJa8JXnhfNHK4BG66BPxzOc37eT9bAErbMxuIsVTo1w7qa0DOEK4OBzf2EDsL\n" +
                                            "qf2z4+lxMoqUz/MS/FQiA8PVV+u///vjaST3l0cNUxQe4pu5uYTBeUFAZSh1FusL\n" +
                                            "GTuzhm71KDf9Jfom6rzOQi7ErpdKWAtKR3YsvKElinPQUMSVs8BCAbJ9ln2+vfQH\n" +
                                            "gptpMwEy3hcU9/j5OfZjW13iWd2uQAtHt32DABEBAAH+AwMCSrR2gQGrRyO6kcnE\n" +
                                            "a4vdSf2b7VCk7dRPyLTvtObt1JrNO3DQfRoHii7MqBWIl5O7DO8+m8zZ/cJ3b/9F\n" +
                                            "HqnZn4I5DWqHqhqjf/CxmYgtKz4bZZCuQ9P9XjjidfkwHwdAsT2E2QU7Xf4sjxmw\n" +
                                            "jsOvylyUACODpomIv3ljVDiD1RvJLxNkGMKePe9bK2md9lH4rBGJHR2Q/ejTCfwh\n" +
                                            "nnts++1mXqVtnGOtVt4p2jFNjWv+x5WkB9pyEoH4d3gYgnACm6Pf5zHx8DddidvB\n" +
                                            "8Klx6JdCOEZQ4lWT4LV5J2BrfX15fRethCUn4SD5TJfXj0YG1+LI/7taYoVLgHGD\n" +
                                            "lDhXORfHVqPJpsheK8jpnapVGjMdKqcth/dSLytxZVRLt8NVc8WfKhVHe0C+LWlR\n" +
                                            "y08gYA7+YcVpQ/Pm6k+GsZDPemXn8ZcgLRX7f1zH+0J8Frl+4nS3to0wewIbCJbt\n" +
                                            "6PgTXgRmNOI98ViJdUwNYdVZtPnkTieZ/5WN8dHLOhScAq/kipi3EfDQckMFn7PC\n" +
                                            "87ikB+60+SozcXv/ptDZv7O7dikgI3hoQHKBpP6P7dH4jAGLoO2XSeJqZ4MrWzVU\n" +
                                            "RfFuc+YTSmFdDww1QgLDw0kTdWdeLIr321LU7yElTNb2mbLMH0A7U3flLfzMFYA7\n" +
                                            "HaRWazgYu/Ai4cCAl51GtdxnPL3TC7jWJqcvAy29I/cgxnE+Z9rLAwQtP1Z2+yAq\n" +
                                            "eGrGIFGajj6Qqpp23XZ45VcgWRi9bgSDXxbv4P3ta0J7wMVaM6DqjWe70dMxjzCE\n" +
                                            "xJd2y7dUKgnicHSO+/LIw9B/8j7zKIbNmEamt9c3YnYQn2DKfC4ZjnrGijscaMOZ\n" +
                                            "P8gNppH2YuyDdG4FD7YPuK5+y7G9oAwT9Ehropr6HZYF7Dh8nHz68DbrCVmLjnL3\n" +
                                            "vrQvamFzb24gKHRlc3QpIDxqYXNvbmdvaGh4QGhsYmIuaG9uZ2xlb25nLmNvbS5t\n" +
                                            "eT6JATkEEwEIACMFAlZEblcCGwMHCwkIBwMCAQYVCAIJCgsEFgIDAQIeAQIXgAAK\n" +
                                            "CRC7fymhR9pzteg7B/9oRtRlqD5PmKTh22fiy+EYD8KrhdvUQf/bsWyMn15dD7CY\n" +
                                            "EqdnQo9I5ey5X3TEVtXHLDDVcKHIoQoLRqt3lxMzRqsFoNMCujV1/cR4jdi22ah+\n" +
                                            "zD/4v7tGe2U4PEd0nwm2zdm97UUzDgRwMwtXolo2LRERdvIbDuNOJdtlIaJ6GTZ6\n" +
                                            "7kidDJs7C60MFQwn1rR2yVpBarBTHKIHf0jZt+gac6hvfErt1Pg90BcL0gAVouQk\n" +
                                            "6PpARPsWkHN+IxFiO512PxpOPntR/HcDv1hSne6XiRopvIxGeL5nlS8q1YZ2Aa4b\n" +
                                            "ah2L0wONYOcvIQsuI9RrZbi8H0qojtjgohtNChkMnQO+BFZEblcBCACuO7mz6uZh\n" +
                                            "H+CjfgmLA69Wp1HGhUtT/Fl3E0dRlgCRI2LN0SoDB8mgUCoBpugAFidTIye5L61R\n" +
                                            "5vH1ntbZzEqcmHIK2LJWCUvQTx/DhrZr/HkSTJcOX9Ay3kWSUT5NUjRHy5AxIBmL\n" +
                                            "Nm/zVSi52t0LFhgoQq0qJQ6gPiapr1OKhFyq0zydnTYYUH1WG++Je8cHVQWcQN07\n" +
                                            "S/mPyUrVVpasJzdo2P+QGV23/p7pgN5pQeiwK7V2Di4OJBsZZLgMuPerUsGsmVpx\n" +
                                            "vKuxlA1/cuuzG2PAg2di/6fvm67VRaLjzwtV94YnK0myQzlQzI+eFJD/PAo1sGKD\n" +
                                            "C7IlfL5JXML3ABEBAAH+AwMCSrR2gQGrRyO6AUK59BCbmaLWOaCMHj4LmdYqv1+o\n" +
                                            "h4yNv33jQQqZ2pckLGDKhD1pqS4uIHTUJGDhlMyubKIsLneBAwlFJ2qMb0chb9KX\n" +
                                            "gIC/gxIq9kymwaiI1vJRaizwxZ6aM8O4+CjrREbL0WbtkjoyqFjvoplLZLQf+bIc\n" +
                                            "eH1w+GCv+W+shyrnur5ZY/ZtyEy7biQWad4hEnttWfWgK2yhCBfL7QFqUHhc9awY\n" +
                                            "agpHjWSt0LNbB2eqThLRGa31q56EPK7A9deKi3oQGQJHTnsjcPUrQ6sODyDsaHk3\n" +
                                            "fJei4iH5MioQonsMdMpgPOfZf+rn4BIbKTvt2hRt7aFXpsotnKEKC2eAkbdDgGiW\n" +
                                            "zw1QOs3c51C/MzUqQPuEIHx54hU4/WppbscIRbU8d4Ne70GLWlvU2+YnanPghnje\n" +
                                            "S5C3NfYXB0jNPUfW2dgiGzTNvNSrzBvJpnYxpZ3gYmc0mBoL45aFn46e+ncu8REs\n" +
                                            "i4wCmr8gTnPd1aUMHLwvLRzyi82cIIZrlIMoIBDKR33PJApMuS0uTgTnnUqJolbl\n" +
                                            "AHE27bbIJrQF8Jn9g82TIBErVCvOcrtVOJy6x4tgV6mPFHslfhj96IVVAUEGrmDF\n" +
                                            "XlJrLsmPrRdMbTKqkTcC1t9e+kaAZdwBO/lgnUYVDQlIAv2zB7yFCtog8mZi9XZ9\n" +
                                            "R1ti7Fa/b27XKL6Cm17S8Lnr3AFRJ1wbjRpeGZG4iSWeUfEUs4xS2sbBxwEcK+Ur\n" +
                                            "rxqPzEtkJ4z10wYt3HaxkljhYGmqtBH/Q1/SGhk3vWolqpcp0rBhBVW46Ww3qKrz\n" +
                                            "H0/eQh/iy0MFtW1HHT2y6CpY8j8dgnr85bJm81ERlACQaUi0nxKd8stY47Lz8Yzs\n" +
                                            "3+VKMy4Wl2j9Rs5Yixxa1Hd3O4HvJ9dVDMhLNcSyAYkBHwQYAQgACQUCVkRuVwIb\n" +
                                            "DAAKCRC7fymhR9pztYe7B/9gNXSJBWCbs3kKd1O3H8WlIvLB7z7vQO2NOSqrchE+\n" +
                                            "WkHkkS/r67XzfSG5R8paSP45BonBGp+0XyCAAYnHaXXPkYYdJ25fKyWx8uZuW6YS\n" +
                                            "bI0q4CQEXJlqFoQWNzHaRfhtlnKJqEbKLoJ6N1DgoGNRV8kapNGI3QIQ3419xxyE\n" +
                                            "+Gv+/2DU0yPUGyc85BuPXLl+4EAnfQu2SXJ5QWj6tdGW8HdEyLcK0O+LEAK/2yHV\n" +
                                            "wUDbK5bag/YwzOZnHC3dojpbYo8Ufw2cxIu49s2J2S1wnEzcX+kDp36Im71q5wyb\n" +
                                            "xZYE6SRNeyy8cAhBkdMCcUDmVV/QGRaCZj2djCvPaQmy\n" +
                                            "=LLLi\n" +
                                            "-----END PGP PRIVATE KEY BLOCK-----\n";

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		encryptAsciiFile();
		decryptFile();
        encryptAndSignFileAscii();
        encryptAndSignFileBinary();
        decryptSignedFileBinary();
		decryptSignedFile();
		decryptSignedFile1();
		decryptSignedFileWithoutSignatureVerification();
		encryptAndSignFileHLB();
		decryptSignedFileHLB();
	}

	public static void encryptAsciiFile() throws Exception {
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

    public static void encryptAndSignFileAscii() throws Exception {
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setCheckIntegrity(true);
        encryptor.setArmored(true);
        encryptor.setPublicKeyFilePath("./test.gpg.pub");
        encryptor.setSigning(true);
        // encryptor.setSigningPrivateKeyFilePath("wahaha.gpg.prv");
        // encryptor.setSigningPrivateKeyPassword("password");
        encryptor.setSigningPrivateKeyString(hlbSecKey);
        encryptor.setSigningPrivateKeyPassword("Hlb!1234");

        encryptor.encryptFile("./test.txt", "./test.txt.signed.enc");
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
//		decryptor.setPrivateKeyFilePath("./bin/keys/hlb_sec.key");
        decryptor.setPrivateKey(hlbSecKey);
        decryptor.setPassword("Hlb!1234");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath("./bin/keys/pub.key");

        System.out.println(decryptor.decryptFile("test2.txt.signed.enc"));
    }

    public static void encryptAndSignFileBinary() throws Exception {
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath("./test.gpg.pub");
        encryptor.setSigning(true);
        // encryptor.setSigningPrivateKeyFilePath("wahaha.gpg.prv");
        // encryptor.setSigningPrivateKeyPassword("password");
        encryptor.setSigningPrivateKeyFilePath("secret.key");
        encryptor.setSigningPrivateKeyPassword("Hlb!1234");

        encryptor.encryptFile("./test.txt", "./test.txt.signed.bin");
    }

    public static void decryptSignedFileBinary() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("test.gpg.prv");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath("public.key");

        System.out.println(decryptor.decryptFile("test.txt.signed.bin"));
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