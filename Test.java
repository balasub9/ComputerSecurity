import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

public class Test {

    public static void main(String[] args) throws Exception {

        // Generate RSA key pair
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt file with public key
        File inputFile = new File("input_text_1KB.txt");
       
        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[190];
        byte[] encryptedBytes;

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        File encryptedFile = new File("encrypted.txt");
        FileOutputStream outputStream = new FileOutputStream(encryptedFile);

        int bytesRead;
        while ((bytesRead = inputStream.read(inputBytes)) != -1) {
            encryptedBytes = cipher.doFinal(inputBytes, 0, bytesRead);
            outputStream.write(encryptedBytes);
        }

        inputStream.close();
        outputStream.close();

        // Decrypt file with private key
        FileInputStream encryptedInputStream = new FileInputStream(encryptedFile);
        byte[] encryptedInputBytes = new byte[256];
        byte[] decryptedBytes;

        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        File decryptedFile = new File("decrypted.txt");
        FileOutputStream decryptedOutputStream = new FileOutputStream(decryptedFile);

        while ((bytesRead = encryptedInputStream.read(encryptedInputBytes)) != -1) {
            decryptedBytes = cipher.doFinal(encryptedInputBytes, 0, bytesRead);
            decryptedOutputStream.write(decryptedBytes);
        }

        encryptedInputStream.close();
        decryptedOutputStream.close();

        System.out.println("Encryption and decryption completed successfully.");
    }
}
