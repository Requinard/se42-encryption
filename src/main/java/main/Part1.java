package main;

import rsa.RsaProxy;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * Created by David on 19-6-2016.
 */
public class Part1 {
    public static void main(String[] args) {
        RsaProxy rsaProxy = new RsaProxy();

        try {
            // generate keypair
            KeyPair keyPair = rsaProxy.generatePair();

            rsaProxy.SaveKeyPair("./keys/", keyPair);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
