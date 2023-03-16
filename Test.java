import java.io.*;
import java.nio.file.Files;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Test {


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
        String inputFile = "input_text_1MB.txt";
        String ip2 = "input_text_10MB.txt";


        hashingSHA(inputFile, "SHA-256");
        hashingSHA(ip2, "SHA-256");
        hashingSHA(inputFile, "SHA-512");
        hashingSHA(ip2, "SHA-512");
        hashingSHA(inputFile, "SHA3-256");
        hashingSHA(ip2, "SHA3-256");

    }

    private static byte[] hashingSHA(String fileName, String algorithm) throws NoSuchAlgorithmException, IOException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        FileInputStream fis = new FileInputStream(fileName);
        byte[] bytesToRead = new byte[8192];
        int noOfBytes = 0;
        while ((noOfBytes = fis.read(bytesToRead)) != -1) {
            messageDigest.update(bytesToRead, 0, noOfBytes);
        }
        fis.close();
        timer.startTimer();
        byte[] hashedOutput= messageDigest.digest();
        long timeElapsed = timer.getExectionTimeIn(NANOSECONDS);
        System.out.println(algorithm+ " Hasing Completed in " + timeElapsed + NANOSECONDS);
        return hashedOutput;
    }
}
