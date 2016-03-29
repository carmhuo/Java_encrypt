package encrypt.PBE;

import java.net.URLEncoder;
import java.security.Key;     
import java.security.SecureRandom;
    
import javax.crypto.Cipher;     
import javax.crypto.SecretKey;     
import javax.crypto.SecretKeyFactory;     
import javax.crypto.spec.PBEKeySpec;     
import javax.crypto.spec.PBEParameterSpec;     

import encrypt.PBE.Base64;
import encrypt.PBE.PBECoder;

/**    
 *   
 * PBE<Password Based Encryption> 基於口令算法  
 * @author carm    
 * @date 2016/3/29   
 */    
public class PBECoder {     
    /**    
     * 支持以下任意算法    
     * PBEWithMD5AndDES     
     * PBEWithMD5AndTripleDES     
     * PBEWithSHA1AndDESede    
     * PBEWithSHA1AndRC2_40    
     */    
    public static final String ALGORITHM = "PBEWITHMD5andDES";     
    
    /**    
     * 盐初始化    
     *     
     * @return    
     * @throws Exception    
     */    
    public static byte[] initSalt() throws Exception {     
        byte[] salt;     
        SecureRandom random = new SecureRandom();     
        salt = random.generateSeed(8);     
        return salt;     
    }     
    
    /**    
     * 口令转换密钥< br>    
     *     
     * @param password    
     * @return    
     * @throws Exception    
     */    
    private static Key toKey(String password) throws Exception {     
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());     
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);     
        SecretKey secretKey = keyFactory.generateSecret(keySpec);     
    
        return secretKey;     
    }     
    
    /**    
     * 加密    
     * @param data    
     * @param password    
     * @param salt    
     */    
    public static String encrypt(byte[] data, String password, byte[] salt)     
            throws Exception {     
        Key key = toKey(password);     
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 100);     
        Cipher cipher = Cipher.getInstance(ALGORITHM);     
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec); 
        byte [] result =cipher.doFinal(data);
        
        return Base64.encode(result);    
    
    }     
    
    /**    
     * 解密    
     * @param data    
     * @param password    
     * @param salt    
     */    
    public static byte[] decrypt(String data, String password, byte[] salt)     
            throws Exception {     
    
        Key key = toKey(password);     
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 100);     
        Cipher cipher = Cipher.getInstance(ALGORITHM);     
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);     
        
        return cipher.doFinal(Base64.decode(data));  
        
    } 
    
    public static String urlEncoder() throws Exception{
    	byte [] sault=PBECoder.initSalt();
    	String b2 = PBECoder.encrypt("5".getBytes(), "carm", sault);
    	return URLEncoder.encode(b2, "utf-8");
    }
    
    public static String urlDecoder(){
		
    	return null;
    	
    }
    
    /**
     * Test
     * @param args
     * @throws Exception
     */
    public static void main(String []args) throws Exception{
    	byte [] sault=PBECoder.initSalt();
		System.out.println("sault："+Base64.encode(sault));
		String b2 = PBECoder.encrypt("5".getBytes(), "carm", sault);
		System.out.println("密文："+b2);
		byte [] b3 = PBECoder.decrypt(b2, "carm", sault);
		System.out.println("明文："+new String(b3));
	}
}   