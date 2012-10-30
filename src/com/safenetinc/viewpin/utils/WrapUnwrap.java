/* second check in */
package  com.safenetinc.viewpin.utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * 
 * @author Pmalik
 *implements the methods to wrap/unwrap the key
 */

public class WrapUnwrap {
   
    /**
     * Wraps a secretkey
     * @param wrappedKey The wrapped session key
     * @param wrappingTransformation The wrapping transformation associated with this operation
     * @param wrappingKey The wrapping key
     * @param wrappedKeyAlgorithm The wrapped key Algorithim
     * @return The unwrapped session key
     * @throws NoSuchPaddingException Thrown if an invalid padding form is specified
     * @throws NoSuchAlgorithmException Thrown if an invalid algorithm is specified
     * @throws InvalidKeyException Thrown id the wrapping key is invalid
     */
    
	public static byte[] wrapKey(Certificate wrappingCertificate, String wrappingTransformation, Key secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, IllegalBlockSizeException
	{
		byte[] wrappedSecretKey;
		Cipher c;
		
		wrappedSecretKey = null;
		c = null;
		
		
		
		 // Instantiate wrapping cipher
	    c = Cipher.getInstance(wrappingTransformation);
		
	    // Initialise wrapping cipher
	    c.init(Cipher.WRAP_MODE, wrappingCertificate);
	    
	  
	    
	    // Wrap session key
		wrappedSecretKey = c.wrap((SecretKey)secretKey);
		
		
		
		return wrappedSecretKey;
	}
    
    /**
     * Unwraps a wrapped session key
     * @param wrappedKey The wrapped session key
     * @param wrappingTransformation The wrapping transformation associated with this operation
     * @param wrappingKey The wrapping key
     * @param wrappedKeyAlgorithm The wrapped key Algorithim
     * @return The unwrapped session key
     * @throws NoSuchPaddingException Thrown if an invalid padding form is specified
     * @throws NoSuchAlgorithmException Thrown if an invalid algorithm is specified
     * @throws InvalidKeyException Thrown id the wrapping key is invalid
     */
    public static Key unwrapKey(byte[] wrappedKey, String wrappingTransformation, PrivateKey wrappingKey, String wrappedKeyAlgorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException
    {
        Key secretKey;
        Cipher c;
        
        secretKey = null;
        c = null;
        
            
       
        
        // Instantiate wrapping cipher
        c = Cipher.getInstance(wrappingTransformation);
        
        // Initialise wrapping cipher
        c.init(Cipher.UNWRAP_MODE, wrappingKey);

        System.out.println("unwrapping secret key");
        
        // Unwrap session key
    //    secretKey = c.unwrap(wrappedKey,"DES", Cipher.SECRET_KEY);
	    secretKey = c.unwrap(wrappedKey,wrappedKeyAlgorithm, Cipher.SECRET_KEY);
	   
        
        System.out.println("unwrapped secret key");
        
        return secretKey;
    }
    
 }
