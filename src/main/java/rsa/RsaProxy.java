package rsa;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;

/**
 * Proxies RSA related tasks
 * <p>
 * For reading and writing keypairs
 * http://snipplr.com/view/18368/
 * <p>
 * For generating keypairs
 * http://stackoverflow.com/questions/1709441/generate-rsa-key-pair-and-encode-private-as-string
 */
public class RsaProxy {
    private static final Logger logger = Logger.getLogger(RsaProxy.class.getName());

    /**
     * Generates a keypair
     */
    public KeyPair generatePair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);

        KeyPair keyPair = keyGen.generateKeyPair();

        logKeyPar(keyPair);
        return keyPair;
    }

    private void logKeyPar(KeyPair keyPair) {
        byte[] publicKey = keyPair.getPublic().getEncoded();
        StringBuffer publicKeyString = new StringBuffer();
        for (int i = 0; i < publicKey.length; ++i) {
            publicKeyString.append(Integer.toHexString(0x0100 + (publicKey[i] & 0x00FF)).substring(1));
        }

        logger.fine(String.format("Public key:\n %s", publicKeyString.toString()));
    }

    private void dumpKeyPair(KeyPair keyPair) {
        PublicKey pub = keyPair.getPublic();
        System.out.println("Public Key: " + getHexString(pub.getEncoded()));

        PrivateKey priv = keyPair.getPrivate();
        System.out.println("Private Key: " + getHexString(priv.getEncoded()));
    }

    private String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    public void SaveKeyPair(String path, KeyPair keyPair) throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(path + "/public.key");
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey.getEncoded());
        fos = new FileOutputStream(path + "/private.key");
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

    public KeyPair LoadKeyPair(String path)
            throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        // Read Public Key.
        File filePublicKey = new File(path + "/public.key");
        FileInputStream fis = new FileInputStream(path + "/public.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        // Read Private Key.
        File filePrivateKey = new File(path + "/private.key");
        fis = new FileInputStream(path + "/private.key");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);
    }
}
