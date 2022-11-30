import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;

import javax.crypto.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ElGamal {

    static SecureRandom random = new SecureRandom();

    public static ElGamalPublicKey getPublicKey(String base64PublicKey) {

        ElGamalPublicKey publicKey = null;
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("ElGamal");
            publicKey = (ElGamalPublicKey)keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return publicKey;
        }
    }

    public static ElGamalPrivateKey getPrivateKey(String base64PrivateKey) {
        ElGamalPrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;

        try {
            keyFactory = KeyFactory.getInstance("ElGamal");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            assert keyFactory != null;

            privateKey = (ElGamalPrivateKey)keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return privateKey;
    }

    public static byte[] encrypt(String data, String publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey), random);
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(String data, String base64PrivateKey) throws Exception {
        return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey));
    }
}