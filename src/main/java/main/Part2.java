package main;

import com.google.common.io.Files;
import rsa.RsaProxy;

import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * takes an input and encrypts a file
 * https://docs.oracle.com/javase/tutorial/security/apisign/step3.html
 */
public class Part2 {
    private static final String signatureType = "SHA1withRSA";

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        RsaProxy rsaProxy = new RsaProxy();

        KeyPair keyPair = rsaProxy.LoadKeyPair("./keys/");

        String fileData = Files.toString(new File("./files/input.ext"), Charset.defaultCharset());

        final byte[] signature = sign(keyPair, fileData);

        writeSignedFile(fileData, signature, "LK");
    }

    private static void writeSignedFile(String fileData, byte[] signature, String signedBy) throws IOException {
        FileOutputStream fos = new FileOutputStream(String.format("./files/INPUT(SIGNEDBY%s).ext", signedBy));
        OutputStreamWriter osw = new OutputStreamWriter(fos);

        // Write sig length
        osw.write(String.format("%s\n", signature.length));

        //write sig
        osw.write(String.format("%s\n", signature.));

        // write data
        osw.write(String.format("%s\n", fileData.getBytes()));

        osw.close();
        fos.close();
    }

    private static byte[] sign(KeyPair keyPair, String fileData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sha1 = Signature.getInstance(signatureType);

        sha1.initSign(keyPair.getPrivate());

        sha1.update(fileData.getBytes());

        return sha1.sign();
    }
}
