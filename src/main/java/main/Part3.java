package main;

import com.google.common.io.Files;
import rsa.RsaProxy;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by David on 19-6-2016.
 */
public class Part3 {
    private static byte byteLen;
    private static byte[] sig = new byte[]{};
    private static byte[] data = new byte[]{};

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        RsaProxy rsaProxy = new RsaProxy();

        KeyPair keyPair = rsaProxy.LoadKeyPair("./keys/");


        read();
    }

    private static void read() throws IOException {
        File f = new File("./files/INPUT(SIGNEDBYLK).ext");
        FileInputStream fis = new FileInputStream(f);

        byteLen = (byte) fis.read();

        fis.read(sig, 1, byteLen);
    }
}
