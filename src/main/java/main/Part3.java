package main;

import com.google.common.io.Files;
import rsa.RsaProxy;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by David on 19-6-2016.
 */
public class Part3 {
    private static int byteLen;
    private static byte[] sig = new byte[]{};
    private static byte[] data = new byte[]{};

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        RsaProxy rsaProxy = new RsaProxy();

        KeyPair keyPair = rsaProxy.LoadKeyPair("./keys/");

        read();

        Signature s = Signature.getInstance(Part2.signatureType);

        s.initVerify(keyPair.getPublic());

        s.update(data);

        boolean verifies = s.verify(sig);

        System.out.println("signature verifies: " + verifies);

    }

    private static void read() throws IOException {
        File f = new File("./files/INPUT(SIGNEDBYLK).ext");
        FileInputStream fis = new FileInputStream(f);

        byteLen = Math.abs(fis.read());

        sig = new byte[byteLen];
        data = new byte[(int) (f.length() - 1 - byteLen)];

        for(int i = 0; i!= byteLen;i++){
            sig[i] = (byte) fis.read();
        }

        int i = 0;

        while(fis.available()> 0){
            data[i++] = (byte) fis.read();
        }

        System.out.println(new String(data, Charset.defaultCharset()));
    }
}
