import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class DES {

    private static final IvParameterSpec ivParameterSpec;

    static {
        try {
            ivParameterSpec = CryptoUtils.getIVSecureRandom("DES");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encrypt(String data, SecretKey secretkey) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretkey, ivParameterSpec);
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data, SecretKey secretkey) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretkey, ivParameterSpec);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(String data, SecretKey secretkey) throws Exception {
        return decrypt(Base64.getDecoder().decode(data.getBytes()), secretkey);
    }
}

