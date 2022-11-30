import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

public class Main {
    static long startTime;
    static long endTime;
    static String encryptedString;
    static String decryptedString;
    static String publicKeyRSA;
    static String privateKeyRSA;
    static String publicKeyElGamal;
    static String privateKeyElGamal;
    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            AESKeyGenerator aesGenerator = new AESKeyGenerator();
            String secretKey = Base64.getEncoder().encodeToString(aesGenerator.getSecretKey().getEncoded());
            SecretKey secretKeyDES = KeyGenerator.getInstance("DES").generateKey();

            RSAKeyPairGenerator keyPairGeneratorRSA = new RSAKeyPairGenerator();
            ElGamalKeyPairGenerator keyPairGeneratorElGamal = new ElGamalKeyPairGenerator();
            publicKeyRSA = Base64.getEncoder().encodeToString(keyPairGeneratorRSA.getPublicKey().getEncoded());
            privateKeyRSA = Base64.getEncoder().encodeToString(keyPairGeneratorRSA.getPrivateKey().getEncoded());
            publicKeyElGamal = Base64.getEncoder().encodeToString(keyPairGeneratorElGamal.getPublicKey().getEncoded());
            privateKeyElGamal = Base64.getEncoder().encodeToString(keyPairGeneratorElGamal.getPrivateKey().getEncoded());

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(DES.encrypt
                        (CryptoUtils.generateRandomString(50), secretKeyDES));
                decryptedString = DES.decrypt(encryptedString, secretKeyDES);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 50  ���� | DES | " + ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = AES.aesEncryptString(CryptoUtils.generateRandomString(50), secretKey);
                decryptedString = AES.aesDecryptString(encryptedString, secretKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 50  ���� | AES | " +  ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(RSA.encrypt
                        (CryptoUtils.generateRandomString(50), publicKeyRSA));
                decryptedString = RSA.decrypt(encryptedString, privateKeyRSA);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 50  ���� | RSA | " +  ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(ElGamal.encrypt
                        (CryptoUtils.generateRandomString(50), publicKeyElGamal));
                decryptedString = ElGamal.decrypt(encryptedString, privateKeyElGamal);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 50  ���� | ElG | " +  ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = AES.aesEncryptString(CryptoUtils.generateRandomString(117), secretKey);
                decryptedString = AES.aesDecryptString(encryptedString, secretKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 117 ���� | AES | " +  ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(RSA.encrypt
                        (CryptoUtils.generateRandomString(117), publicKeyRSA));
                decryptedString = RSA.decrypt(encryptedString, privateKeyRSA);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 117 ���� | RSA | " +  ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(DES.encrypt
                        (CryptoUtils.generateRandomString(117), secretKeyDES));
                decryptedString = DES.decrypt(encryptedString, secretKeyDES);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 117 ���� | DES | " +  ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(ElGamal.encrypt
                        (CryptoUtils.generateRandomString(117), publicKeyElGamal));
                decryptedString = ElGamal.decrypt(encryptedString, privateKeyElGamal);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 117 ���� | ElG | " +  ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(RSA.encrypt
                        (CryptoUtils.generateRandomString(80), publicKeyRSA));
                decryptedString = RSA.decrypt(encryptedString, privateKeyRSA);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 80  ���� | RSA | " +  ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(DES.encrypt
                        (CryptoUtils.generateRandomString(80), secretKeyDES));
                decryptedString = DES.decrypt(encryptedString, secretKeyDES);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 80  ���� | DES | " +  ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(ElGamal.encrypt
                        (CryptoUtils.generateRandomString(80), publicKeyElGamal));
                decryptedString = ElGamal.decrypt(encryptedString, privateKeyElGamal);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 80  ���� | ElG | " +  ((endTime - startTime)/1000F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = AES.aesEncryptString(CryptoUtils.generateRandomString(80), secretKey);
                decryptedString = AES.aesDecryptString(encryptedString, secretKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 80  ���� | AES | " +  ((endTime - startTime)/1000.0F) + " ������");


            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(DES.encrypt
                        (CryptoUtils.generateRandomString(100), secretKeyDES));
                decryptedString = DES.decrypt(encryptedString, secretKeyDES);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 100 ���� | DES | " + ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = AES.aesEncryptString(CryptoUtils.generateRandomString(100), secretKey);
                decryptedString = AES.aesDecryptString(encryptedString, secretKey);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 100 ���� | AES | " +  ((endTime - startTime)/1000.0F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(ElGamal.encrypt
                        (CryptoUtils.generateRandomString(100), publicKeyElGamal));
                decryptedString = ElGamal.decrypt(encryptedString, privateKeyElGamal);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 100 ���� | ElG | " +  ((endTime - startTime)/1000F) + " ������");

            startTime = System.currentTimeMillis();
            for (int i = 0; i < 1000; i++)
            {
                encryptedString = Base64.getEncoder().encodeToString(RSA.encrypt
                        (CryptoUtils.generateRandomString(100), publicKeyRSA));
                decryptedString = RSA.decrypt(encryptedString, privateKeyRSA);
            }
            endTime = System.currentTimeMillis();
            System.out.println("2000 ���������� | 100 ���� | RSA | " +  ((endTime - startTime)/1000.0F) + " ������");

        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
        }
    }
}
