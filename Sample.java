import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Sample {

    public static final Timer timer = new Timer();
    public static final String AES_CBC = "AES/CBC/PKCS5Padding";
    public static final String AES_CTR = "AES/CTR/NoPadding";
    public static final String RSA_OAEP = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    public static final String AES_CTR_MODE = "AES(CTR MODE)";
    public static final String AES_CBC_MODE = "AES(CBC MODE)";
    public static final String RSA_OAEP_MODE = "RSA(OAEP)";
    public static final String ENC_ALGO_AES = "AES";
    public static final String ENC_ALGO_RSA = "RSA";
    public static final String MILLISECONDS = "milliseconds";
    public static final String NANOSECONDS = "nanoseconds";
    public static final int KEY_SIZE_128 = 128;
    public static final int KEY_SIZE_256 = 256;
    public static final int KEY_SIZE_2048 = 2048;
    public static final int KEY_SIZE_3072 = 3072;
    public static final String filePrefix = "input_text_";

    public static void main(String[] args) throws Exception {
        deleteFiles();
        File oneKbFile = new File(filePrefix + "1KB.txt");
        File oneMBFile = new File(filePrefix + "1MB.txt");
        File tenMBFile = new File(filePrefix + "10MB.txt");
        // Converting Files to Bytes
        SecretKey secretkey = getSecretKeyFor(KEY_SIZE_128, ENC_ALGO_AES);
        SecretKey secretkey256 = getSecretKeyFor(KEY_SIZE_256, ENC_ALGO_AES);
        KeyPair secretkey2048 = getSecretKeyPairFor(KEY_SIZE_2048, ENC_ALGO_RSA);
        KeyPair secretkey3072 = getSecretKeyPairFor(KEY_SIZE_3072, ENC_ALGO_RSA);

        byte[] binaryOneKbFile = convertFileIntoBytes(oneKbFile);
        byte[] binaryTenMbFile = convertFileIntoBytes(tenMBFile);
        byte[] binaryOneMbFile = convertFileIntoBytes(oneMBFile);
        pt("DATA SIZE IS " + binaryOneKbFile.length);
        int encBlockSize = 0, decryptionBlocksize = 0;
        // Secion A
        encryptAndDecrypt(ENC_ALGO_AES, AES_CBC_MODE, AES_CBC, null, secretkey, binaryOneKbFile, "1KB",
                getInitializationVector(), KEY_SIZE_128, encBlockSize, decryptionBlocksize);

        encryptAndDecrypt(ENC_ALGO_AES, AES_CBC_MODE, AES_CBC, null, secretkey, binaryTenMbFile, "10MB",
                getInitializationVector(), KEY_SIZE_128, encBlockSize, decryptionBlocksize);

        // Secion B
        encryptAndDecrypt(ENC_ALGO_AES, AES_CTR_MODE, AES_CTR, null, secretkey, binaryOneKbFile, "1KB",
                getInitializationVector(), KEY_SIZE_128, encBlockSize, decryptionBlocksize);

        encryptAndDecrypt(ENC_ALGO_AES, AES_CTR_MODE, AES_CTR, null, secretkey, binaryTenMbFile, "10MB",
                getInitializationVector(), KEY_SIZE_128, encBlockSize, decryptionBlocksize);

        // Secion C
        encryptAndDecrypt(ENC_ALGO_AES, AES_CTR_MODE, AES_CTR, null, secretkey256, binaryOneKbFile, "1KB",
                getInitializationVector(), KEY_SIZE_256, encBlockSize, decryptionBlocksize);

        encryptAndDecrypt(ENC_ALGO_AES, AES_CTR_MODE, AES_CTR, null, secretkey256, binaryTenMbFile, "10MB",
                getInitializationVector(), KEY_SIZE_256, encBlockSize, decryptionBlocksize);

        // Secion D
        encBlockSize = 190;
        decryptionBlocksize = 256;
        encryptAndDecrypt(ENC_ALGO_RSA, RSA_OAEP_MODE, RSA_OAEP, secretkey2048, null, binaryOneKbFile, "1KB",
                null, KEY_SIZE_2048, encBlockSize, decryptionBlocksize);

        encryptAndDecrypt(ENC_ALGO_RSA, RSA_OAEP_MODE, RSA_OAEP, secretkey2048, null, binaryOneMbFile, "1MB",
                null, KEY_SIZE_2048, encBlockSize, decryptionBlocksize);

        // Secion E
        encBlockSize = 318;
        decryptionBlocksize = 384;
        encryptAndDecrypt(ENC_ALGO_RSA, RSA_OAEP_MODE, RSA_OAEP, secretkey3072, null, binaryOneKbFile, "1KB",
                null, KEY_SIZE_3072, encBlockSize, decryptionBlocksize);

        encryptAndDecrypt(ENC_ALGO_RSA, RSA_OAEP_MODE, RSA_OAEP, secretkey3072, null, binaryOneMbFile, "1MB",
                null, KEY_SIZE_3072, encBlockSize, decryptionBlocksize);

    }

    public static void encryptAndDecrypt(String encAlgo, String mode, String algorithm, KeyPair keypair,
            SecretKey secretkey, byte[] binaryfile,
            String filesize, byte[] intitvector, int keysize, int encBlockSize, int decryptionBlocksize)
            throws Exception {
        pt("---------- STARTING  " + mode + "  FOR " + filesize + " FILE using keysize" + keysize + " -------------");

        byte[] encryptedData, decryptedCipher;
        if (encAlgo == ENC_ALGO_RSA) {
            encryptedData = encryptOriginalText(binaryfile, secretkey, keypair.getPublic(), algorithm, intitvector,
                    encBlockSize);
            decryptedCipher = decryptCipher(encryptedData, secretkey, keypair.getPrivate(), algorithm, intitvector,
                    decryptionBlocksize);
        } else {
            encryptedData = encryptOriginalText(binaryfile, secretkey, null, algorithm, intitvector, encBlockSize);
            decryptedCipher = decryptCipher(encryptedData, secretkey, null, algorithm, intitvector,
                    decryptionBlocksize);
        }
        String decryptedoriginalText = new String(decryptedCipher, StandardCharsets.UTF_8);
        String filename = "1_" + encAlgo + "_" + mode + "_KEYSIZE_" + keysize + "_" + filesize;
        writeToFile(decryptedoriginalText, filename);
        // pt("Printing Decrypted text:");
        // pt(decryptedoriginalText);
        pt("-----------   " + mode + "  COMPLETED ----------------");

    }

    /*
     * Print to Console
     */
    public static void pt(String s) {
        System.out.println(s);
    }

    /*
     * Generates a new symmetric encryption key of the specified size and algorithm
     */
    public static SecretKey getSecretKeyFor(int keysize, String encAlgorithm) throws NoSuchAlgorithmException {
        // SecureRandom is a technique to generate cryptographically strong random
        // numbers
        pt("Generating Secret Key of size " + keysize + ".....");
        timer.startTimer();
        SecureRandom randomNumber = SecureRandom.getInstanceStrong();
        // Use keygenrator for generating symmetric encryption keys for AES
        KeyGenerator keygenrator = KeyGenerator.getInstance(encAlgorithm);
        // Initalize keygenrator with keysize and secure Radom generated
        keygenrator.init(keysize, randomNumber);
        SecretKey secretkey = keygenrator.generateKey();
        pt("Sucessfully Generated Secret Key in " + timer.getExectionTimeIn(MILLISECONDS) + "milliseconds");
        return secretkey;
    }

    /*
     * Generates a key pair of a given key size and encryption algorithm
     */
    public static KeyPair getSecretKeyPairFor(int keysize, String encAlgorithm) throws NoSuchAlgorithmException {
        pt("Generating Key pair of size " + keysize + ".....");
        timer.startTimer();
        KeyPairGenerator keygenrator = KeyPairGenerator.getInstance(encAlgorithm);
        keygenrator.initialize(keysize);
        KeyPair keyPair = keygenrator.generateKeyPair();
        pt("Sucessfully Generated Secret Key in " + timer.getExectionTimeIn(MILLISECONDS) + "milliseconds");
        return keyPair;
    }

    /*
     * The initialization vector is a 128 bit random value that
     * initialize the cipher before encryption/decryption
     */
    public static byte[] getInitializationVector() {
        // Initialize a 128 bit /16byte vector
        byte[] initalizationVector = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(initalizationVector);
        return initalizationVector;
    }

    public static byte[] encryptOriginalText(byte[] inputText, SecretKey secretkey,
            PublicKey publicKey, String algorithm, byte[] initvec, int encBlockSize)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        pt(" Encryption Started...");
        timer.startTimer();
        // Create a new Cipher object with required algorithm
        Cipher cipher = Cipher.getInstance(algorithm);
        // Initialize Cipher object with key and initialization vector
        byte[] cipherData;
        if (algorithm.contains(ENC_ALGO_RSA)) {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            ByteBuffer byteBuffer = ByteBuffer.wrap(inputText);
            byte[] batch = new byte[encBlockSize];
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            while (byteBuffer.hasRemaining()) {
                byteBuffer.get(batch, 0, Math.min(byteBuffer.remaining(), encBlockSize));
                byte[] cipherbatch = cipher.doFinal(batch);
                outputStream.write(cipherbatch);
            }
            cipherData = outputStream.toByteArray();
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretkey, new IvParameterSpec(initvec));
            cipherData = cipher.doFinal(inputText);
        }
        // Perform Encryption & return cipertext

        long timeElapsed = timer.getExectionTimeIn(MILLISECONDS);

        pt(" Encryption Completed in " + timeElapsed + MILLISECONDS);
        double decryptionSpeed1 = ((double) cipherData.length / timeElapsed);
        pt(" Encryption Speed is " + decryptionSpeed1 + " bytes/milliseconds");

        return cipherData;
    }

    public static byte[] decryptCipher(byte[] ciphertext, SecretKey secretkey, PrivateKey privateKey, String algorithm,
            byte[] initvec, int decryptionBlockSize)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        pt(" Decryption Started...");
        timer.startTimer();
        // Create a new Cipher object with AES/CBC/PKCS5Padding decryption mode
        Cipher cipher = Cipher.getInstance(algorithm);
        // Initialize the Cipher object with the provided key and initialization vector
        byte[] originalData;
        if (algorithm.contains(ENC_ALGO_RSA)) {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            ByteBuffer byteBuffer = ByteBuffer.wrap(ciphertext);
            byte[] batch = new byte[decryptionBlockSize];
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            while (byteBuffer.hasRemaining()) {
                byteBuffer.get(batch, 0, Math.min(byteBuffer.remaining(), decryptionBlockSize));
                byte[] cipherbatch = cipher.doFinal(batch);
                outputStream.write(cipherbatch);
            }
            originalData = outputStream.toByteArray();
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretkey, new IvParameterSpec(initvec));
            // Decrypt Ciper and return original text
            originalData = cipher.doFinal(ciphertext);
        }
        long timeElapsed = timer.getExectionTimeIn(MILLISECONDS);
        if (timeElapsed > 0)
            pt(" Decryption Completed in " + timeElapsed + MILLISECONDS);
        else
            pt(" Decryption Completed in " + timer.getExectionTimeIn(NANOSECONDS) + " " + NANOSECONDS);

        return originalData;
    }

    /**
     * Reads the contents of the specified file into a byte array.
     */
    public static byte[] convertFileIntoBytes(File file) throws IOException {
        FileInputStream fileinput = new FileInputStream(file);
        // Create a byte array to hold the file contents
        byte[] input = new byte[(int) file.length()];
        // Read the entire file into the byte array
        fileinput.read(input);
        fileinput.close();
        return input;
    }

    // private static byte[] readDataFromFile(File file) throws IOException {
    // ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // try (InputStream is = new FileInputStream(file)) {
    // byte[] buffer = new byte[1024];
    // int bytesRead;
    // while ((bytesRead = is.read(buffer)) != -1) {
    // bos.write(buffer, 0, bytesRead);
    // }
    // }
    // return bos.toByteArray();
    // }

    public static File convertByteArrayToFile(byte[] byteArray, String fileName) throws IOException {
        File file = new File(fileName);
        FileOutputStream outputStream = new FileOutputStream(file);
        outputStream.write(byteArray);
        return file;
    }

    public static void printFirstNLinesOfFile(String myString, int noOfLines) throws IOException {
        String[] lines = myString.split("\\r?\\n");

        // loop over the first n lines and print them
        for (int i = 0; i < noOfLines && i < lines.length; i++) {
            System.out.println(lines[i]);
        }
    }

    public static String decryptedtext(byte[] decrypted) throws UnsupportedEncodingException {
        String plaintext = null;
        String[] charsets = { "UTF-8", "ISO-8859-1", "US-ASCII", "UTF-16" };
        for (String charset : charsets) {
            try {
                plaintext = new String(decrypted, charset);
                break;
            } catch (UnsupportedEncodingException e) {
                // ignore and try the next charset
            }
        }
        if (plaintext == null) {
            throw new UnsupportedEncodingException(
                    "Cannot decode decrypted data with any of the supported character sets.");
        }
        return plaintext;
    }

    public static void writeToFile(String decryptedData, String filename) {
        try {
            File file = new File(filename);
            FileWriter writer = new FileWriter(file);
            writer.write(decryptedData);
            writer.close();
            System.out.println("Successfully wrote decrypted data to file.");
        } catch (IOException e) {
            System.out.println("An error occurred while writing to file: " + e.getMessage());
        }
    }

    public static void deleteFiles() {
        String directory = System.getProperty("user.dir");
        String searchString = "_KEYSIZE_";

        File dir = new File(directory);

        if (dir.isDirectory()) {
            File[] files = dir.listFiles();
            for (File file : files) {
                if (file.isFile() && file.getName().contains(searchString)) {
                    file.delete();
                    System.out.println("Deleted file: " + file.getName());
                }
            }
        } else {
            System.out.println("Directory does not exist.");
        }
    }
}
