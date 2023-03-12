import java.io.*;
import java.nio.file.Files;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Test {
    
    public static void main(String[] args) throws Exception {
        String inputFile = "input_text_1MB.txt";
        String encryptedFile = "encrypted.txt";
        String decryptedFile = "decrypted.txt";

        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(3072);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt the input file
        encryptFile(inputFile, encryptedFile, publicKey);

        // Decrypt the encrypted file
        decryptFile(encryptedFile, decryptedFile, privateKey);

        System.out.println("Encryption and decryption done!");
    }

    public static void encryptFile(String inputFile, String outputFile, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Get the input file size
        long fileSize = new File(inputFile).length();

        // Set the chunk size to encrypt
        int chunkSize = 318; // Maximum size for RSA encryption with 3072-bit key

        // Open input and output streams
        FileInputStream inStream = new FileInputStream(inputFile);
        FileOutputStream outStream = new FileOutputStream(outputFile);

        try {
            byte[] buffer = new byte[chunkSize];
            int bytesRead;

            // Encrypt each chunk and write to the output file
            while ((bytesRead = inStream.read(buffer)) != -1) {
                byte[] encryptedChunk = cipher.doFinal(buffer, 0, bytesRead);
                outStream.write(encryptedChunk);
            }
        } finally {
            inStream.close();
            outStream.close();
        }
    }

    public static void decryptFile(String inputFile, String outputFile, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Get the input file size
        long fileSize = new File(inputFile).length();

        // Set the chunk size to decrypt
        int chunkSize = 384; // Maximum size for RSA decryption with 3072-bit key

        // Open input and output streams
        FileInputStream inStream = new FileInputStream(inputFile);
        FileOutputStream outStream = new FileOutputStream(outputFile);

        try {
            byte[] buffer = new byte[chunkSize];
            int bytesRead;

            // Decrypt each chunk and write to the output file
            while ((bytesRead = inStream.read(buffer)) != -1) {
                byte[] decryptedChunk = cipher.doFinal(buffer, 0, bytesRead);
                outStream.write(decryptedChunk);
            }
        } finally {
            inStream.close();
            outStream.close();
        }
    }
}
