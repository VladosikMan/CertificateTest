package com.vladgad.certificatetest;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;


public class Cryptography {

    private KeyStore serverKeyStore;
    private Context context;
    public final static String LINE_SEPARATOR = System.getProperty("line.separator");

    private final static String mTag = "Cryptography";

    public Cryptography(Context context) {
        try {
            serverKeyStore = KeyStore.getInstance("AndroidKeyStore");

            this.context = context;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public void generateKeys(String alias) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        if (!isSigningKey(alias)) {
            Log.d(mTag, "Generate keys");
            generatePair(alias, context);
        } else {
            Log.d(mTag, "Such a key already exists");
        }
    }

    private void generatePair(String alias, Context context) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        // generate pair keys
        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 30);

      /*  KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setSubject(new X500Principal("CN=" + alias))
                .setSerialNumber(BigInteger.valueOf(Math.abs(alias.hashCode())))
                .setStartDate(start.getTime()).setEndDate(end.getTime())
                .build();*/

        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4))
                .setCertificateSubject(new X500Principal("CN=" + alias))
                // Only permit the private key to be used if the user authenticated
                // within the last five minutes.
                .setKeyValidityStart(start.getTime())
                .setKeyValidityEnd(end.getTime())
                .setCertificateSerialNumber(BigInteger.valueOf(Math.abs(alias.hashCode())))
                .setUserAuthenticationValidityDurationSeconds(5 * 60)

                .build();


        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(
                "RSA",
                "AndroidKeyStore");

        kpGenerator.initialize(spec);

        KeyPair keyPair = kpGenerator.generateKeyPair();
        Log.d(mTag, "Public Key is " + (keyPair.getPublic().toString()).getBytes());


        try {
           /* Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());*/
            // The key pair can also be obtained from the Android Keystore any time as follows:
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);

            int x = 1;
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


    }

    public String encrypt(String alias, String plaintext) {
        try {
            // отправить серверу, где тот его зашифрует
            PublicKey publicKey = getPrivateKeyEntry(alias).getCertificate().getPublicKey();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.encodeToString(cipher.doFinal(plaintext.getBytes()), Base64.NO_WRAP);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String decrypt(String alias, String ciphertext) {
        try {
            PrivateKey privateKey = getPrivateKeyEntry(alias).getPrivateKey();
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public String encrypt(PublicKey publicKey, String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.encodeToString(cipher.doFinal(plaintext.getBytes()), Base64.DEFAULT);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String decrypt(PrivateKey privateKey, String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(Base64.decode(plaintext, Base64.DEFAULT)), "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private KeyStore.PrivateKeyEntry getPrivateKeyEntry(String alias) {
        try {

            serverKeyStore.load(null);
            KeyStore.Entry entry = serverKeyStore.getEntry(alias, null);

            if (entry == null) {
                Log.d(mTag, "No key found under alias: " + alias);
                Log.d(mTag, "Exiting signData()...");
                return null;
            }

            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                Log.d(mTag, "Not an instance of a PrivateKeyEntry");
                Log.d(mTag, "Exiting signData()...");
                return null;
            }
            return (KeyStore.PrivateKeyEntry) entry;
        } catch (Exception e) {
            Log.d(mTag, e.getMessage(), e);
            return null;
        }
    }

    public PublicKey getPublicKey(String alias) {
        Log.d(mTag, getPrivateKeyEntry(alias).getCertificate().getType());
        return getPrivateKeyEntry(alias).getCertificate().getPublicKey();
    }

    public PrivateKey getPrivateKey(String alias) {
        return getPrivateKeyEntry(alias).getPrivateKey();
    }

    public KeyPair getKeyPair(String alias) {
        KeyPair keyPair = new KeyPair(getPrivateKeyEntry(alias).getCertificate().getPublicKey(), getPrivateKeyEntry(alias).getPrivateKey());
        return keyPair;
    }

    public boolean isSigningKey(String alias) {
        try {
            serverKeyStore.load(null);
            return serverKeyStore.containsAlias(alias);
        } catch (Exception e) {
            Log.d(mTag, e.getMessage());
            return false;
        }
    }

    public String getCert(String alias) throws CertificateEncodingException {
        Certificate cert = getPrivateKeyEntry(alias).getCertificate();
        if (cert == null) {
            return null;
        }
        return Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP);
    }

    public X509Certificate geCertificate(String alias) {
        return (X509Certificate) getPrivateKeyEntry(alias).getCertificate();
    }

    public KeyStore getKeyStore() {
        return serverKeyStore;
    }

    public String generateCrt(String alias) throws CertificateEncodingException {
        String crt = "-----BEGIN CERTIFICATE-----" + "\n" + this.getCert(alias) + "\n-----END CERTIFICATE-----";
        return crt;
    }

    private String generatePrivateKeyPEM(String key) {
        String crt = "--Газ---BEGIN PRIVATE KEY-----" + "\n" + key + "\n-----END PRIVATE KEY-----";
        return crt;
    }

    private void writeCrtToFile(String path, String crt) throws IOException, IOException {
        FileOutputStream outputStream = new FileOutputStream(path);
        byte[] strToBytes = crt.getBytes();
        outputStream.write(strToBytes);
        outputStream.close();
    }

    private void savePrivateKey(String key, String path) throws IOException {
        FileOutputStream outputStream = new FileOutputStream(path);
        byte[] strToBytes = key.getBytes();
        outputStream.write(strToBytes);
        outputStream.close();
    }

    public PrivateKey readPrivateKey(File file) throws Exception {
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.decode(privateKeyPEM, Base64.DEFAULT);

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }


    public static Certificate getCert(InputStream inputStream) {
        CertificateFactory cf = null;
        Certificate cert = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
            cert = cf.generateCertificate(inputStream);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return cert;
    }


    public PrivateKey getPrivateKeyFromPath(String path) throws IOException, URISyntaxException, NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(this.getFileFromResourceAsByteArray(path));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(spec);
        return privKey;
    }

    public X509Certificate getCertificateFromPath(String path) throws IOException, CertificateException {
        X509Certificate cert = null;

        InputStream inStream = this.getFileFromResourceAsStream(path);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(inStream);
        return cert;
    }

    private byte[] getFileFromResourceAsByteArray(String fileName) throws URISyntaxException, IOException {
        return Files.readAllBytes(Paths.get(fileName));
    }

    private File getFileFromResource(String fileName) throws URISyntaxException {

        ClassLoader classLoader = getClass().getClassLoader();
        URL resource = classLoader.getResource(fileName);
        if (resource == null) {
            throw new IllegalArgumentException("file not found! " + fileName);
        } else {
            return new File(resource.toURI());
        }

    }

    private InputStream getFileFromResourceAsStream(String fileName) {

        // The class loader that loaded the class
        ClassLoader classLoader = getClass().getClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream(fileName);

        // the stream holding the file content
        if (inputStream == null) {
            throw new IllegalArgumentException("file not found! " + fileName);
        } else {
            return inputStream;
        }
    }

    public static X509Certificate generateV3Certificate(KeyPair pair, String userName) {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X500Principal("CN=" + userName + " Certificate"));
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 11111111111l));
        certGen.setSubjectDN(new X500Principal("CN=" + userName + " Certificate"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");


        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        certGen.addExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

        certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));
        X509Certificate targetCertificate = null;
        try {
            targetCertificate = certGen.generate(pair.getPrivate());
        } catch (NoSuchAlgorithmException e) {
            Log.d(mTag, "NoSuchAlgorithmException Could create a certificate for: " + userName + ".");
        } catch (SignatureException e) {
            Log.d(mTag, "SignatureException Could create a certificate for: " + userName + ".");
        } catch (CertificateEncodingException e) {
            Log.d(mTag, "CertificateEncodingException Could create a certificate for: " + userName + ".");
        } catch (InvalidKeyException e) {
            Log.d(mTag, "InvalidKeyException Could create a certificate for: " + userName + ".");
        }

        return targetCertificate;
    }
}
