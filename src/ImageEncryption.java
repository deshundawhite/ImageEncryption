import com.sun.xml.internal.org.jvnet.fastinfoset.EncodingAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by David on 9/17/2014.
 */
public class ImageEncryption
{
    static final int MAX_RGB_VALUE = 16777215;
    static final int BYTES_IN_DWORD = 4; // 4 bytes are in 32-bit (DWORD) integers

    static String IV = "AAAAAAAAAAAAAAAA";
    static String encryptionKey = "0123456789abcdef"; // for AES 128

    static final String COMMA = ",";

    public static void main(String[] args) throws IOException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        encrypt("in.jpg"); // generates the encrypted.txt file that contains all the encrypted pixel colors
        decrypt("encrypt.txt", "in.jpg"); // decrypts a text file that contains all the encrypted pixel colors
    }
//insert proper headings from commenting style
    public static void encrypt(String fileName) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException
    {
        int width = getImageWidth(fileName);
        int height = getImageHeight(fileName);
        int [] colorArray = getColors(fileName, width, height);

        writeToFile("encrypt.txt","txt", width, height, bytesToIntegers(encryptWithAES(integersToBytes(colorArray), encryptionKey)));
    }

    public static void decrypt(String fileName, String imageName) throws IOException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException 
    {
	int numOfLines = readNumLines(fileName);  
        String [] inputLine = readInFile(numOfLines, fileName);
        int [] encryptedIntegers = convertStringToInt(inputLine);
        String header = getHeader(inputLine);  
        int width = getImageWidth(imageName); 
        int height = getImageHeight(imageName);
        
        createImage((bytesToIntegers(decryptWithAES((integersToBytes(encryptedIntegers)), encryptionKey))),width, height);
    }

    private static byte[] encryptWithAES(byte[] plainText, String encryptionKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        return cipher.doFinal(plainText);
    }

    private static byte[] decryptWithAES(byte[] cipherText, String encryptionKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        return cipher.doFinal(cipherText);
    }

    private static byte[] integersToBytes(int[] data)
    {
        ByteBuffer byteBuffer = ByteBuffer.allocate(data.length * BYTES_IN_DWORD);
        IntBuffer intBuffer = byteBuffer.asIntBuffer();
        intBuffer.put(data);

        return byteBuffer.array();
    }

    private static int[] bytesToIntegers(byte[] bytes)
    {
        IntBuffer intBuf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).asIntBuffer();
        int[] data = new int[intBuf.remaining()];
        intBuf.get(data);

        return data;
    }

    public static void writeToFile(String fileName, String fileFormat, int width, int height, int [] colorPixels) throws IOException
    {
        FileWriter fw = new FileWriter(fileName);
        BufferedWriter out = new BufferedWriter(fw);
        
        String lineSpace = System.getProperty("line.separator"); //sequence used by operating system to separate lines in text files

        String header = fileFormat + COMMA + width + COMMA + height + lineSpace; 
        out.write(header);

        for(int i = 0; i < colorPixels.length; i++)
        {
            out.write(colorPixels[i] + lineSpace);
        }
        
        out.close();
        fw.close();
    }
    
    public static void createImage(int[] colorPixels, int width, int height) throws IOException
    {
        BufferedImage image = new BufferedImage(width, height, BYTES_IN_DWORD);
        
        int arrayInc = 0;
                     
        for (int i = 0; i < height; i++)
        {
            for (int j = 0; j < width; j++)
                {
                    image.setRGB(j, i, colorPixels[arrayInc]);
                    arrayInc++;
                }
        }
        
        File file = new File("decrypt.jpg");
        ImageIO.write(image, "jpg", file);
    }
    
    public static int getImageWidth(String fileName) throws IOException
    {
        File file = new File(fileName); 
        BufferedImage image = ImageIO.read(file);
        
        int width = image.getWidth();
        
        return width;
    }
    
    public static int getImageHeight(String fileName) throws IOException
    {
        File file = new File(fileName); 
        BufferedImage image = ImageIO.read(file);
        
        int height = image.getHeight();
        
        return height;
    }
    
    public static int [] getColors(String fileName, int width, int height) throws IOException
    {
        File file = new File(fileName); 
        BufferedImage image = ImageIO.read(file);
        
        int arrayLength = (height * width);
        
            int [] colorArray = new int[arrayLength];
            int arrayInc = 0;
                     
            for (int i = 0; i < height; i++)
            {
                for (int j = 0; j < width; j++)
                    {
                        int color = image.getRGB(j,i);
                        colorArray [arrayInc] = color;
                        arrayInc++;
                    }
            }
        
        return colorArray; 
    }
    
    public static int readNumLines(String fileName) throws IOException
    {
        FileReader file = new FileReader(fileName);
        BufferedReader reader = new BufferedReader(file);
        
        String line = null;
        int numberOfLines = 0;
        
        while((line = reader.readLine()) != null)
        {
            numberOfLines++;
        }
        reader.close();
        file.close();
        
        return numberOfLines;
    }
    
    public static String[] readInFile(int arrayLength, String fileName) throws IOException
    {
        FileReader file = new FileReader(fileName);
        BufferedReader reader = new BufferedReader(file);
        
        String [] encryptedString = new String [arrayLength];
        
        for(int i = 0; i < (encryptedString.length); i++)
                    {
                        encryptedString[i] = reader.readLine();
                    }
        reader.close();
        file.close();
        
        return encryptedString;
    }
    
   public static int[] convertStringToInt(String [] encryptedString)
    {
        int [] encryptedInt = new int [encryptedString.length - 1];
        
        for(int i = 0; i < encryptedInt.length; i++)
        {
            encryptedInt[i] = Integer.valueOf(encryptedString[i + 1]);
        }
        
        return encryptedInt;
    }
   
   public static String getHeader (String [] encryptedString)
   {
       String introLine = null;
       introLine = encryptedString[0];
       
       return introLine; 
   }
}
