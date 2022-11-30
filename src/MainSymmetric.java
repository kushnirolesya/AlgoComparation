import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class MainSymmetric {
    static long startTime;
    static long endTime;
    static String encryptedString;
    static String decryptedString;

    public static void main(String[] args) throws Exception {
        try {
            AESKeyGenerator aesGenerator = new AESKeyGenerator();
            String secretKey = Base64.getEncoder().encodeToString(aesGenerator.getSecretKey().getEncoded());
            SecretKey secretKeyDES = KeyGenerator.getInstance("DES").generateKey();

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = AES.aesEncryptString(CryptoUtils.generateRandomString(500), secretKey);
                decryptedString = AES.aesDecryptString(encryptedString, secretKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 повідомлень | 500  байт | AES | " + ((endTime - startTime) / 1000.0F) + " секунд");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = AES.aesEncryptString(CryptoUtils.generateRandomString(3000), secretKey);
                decryptedString = AES.aesDecryptString(encryptedString, secretKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 повідомлень | 3000 байт | AES | " + ((endTime - startTime) / 1000.0F) + " секунд");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = AES.aesEncryptString(CryptoUtils.generateRandomString(6000), secretKey);
                decryptedString = AES.aesDecryptString(encryptedString, secretKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 повідомлень | 6000 байт | AES | " + ((endTime - startTime) / 1000.0F) + " секунд");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = Base64.getEncoder().encodeToString(DES.encrypt
                        (CryptoUtils.generateRandomString(500), secretKeyDES));
                decryptedString = DES.decrypt(encryptedString, secretKeyDES);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 повідомлень | 500  байт | DES | " + ((endTime - startTime) / 1000.0F) + " секунд");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = Base64.getEncoder().encodeToString(DES.encrypt
                        (CryptoUtils.generateRandomString(3000), secretKeyDES));
                decryptedString = DES.decrypt(encryptedString, secretKeyDES);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 повідомлень | 3000 байт | DES | " + ((endTime - startTime) / 1000.0F) + " секунд");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++) {
                encryptedString = Base64.getEncoder().encodeToString(DES.encrypt
                        (CryptoUtils.generateRandomString(6000), secretKeyDES));
                decryptedString = DES.decrypt(encryptedString, secretKeyDES);
            }
            endTime = System.currentTimeMillis();
            System.out.println("1000 повідомлень | 6000 байт | DES | " + ((endTime - startTime) / 1000.0F) + " секунд");

        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
        }
    }
}
