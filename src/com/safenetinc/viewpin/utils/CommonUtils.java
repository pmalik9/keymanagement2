// $Id: KeyManagement/src/com/safenetinc/viewpin/utils/CommonUtils.java 1.1 2008/12/01 11:11:24GMT+05:30 Gupta, Rahul (rgupta4) Exp  $
package com.safenetinc.viewpin.utils;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.RSAKeyGenParameterSpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import com.chrysalisits.crypto.LunaTokenManager;

/**
 * Class to handle CommonUtils Luna key managment operations
 * @author Stuart Horler
 *
 *
 */
public class CommonUtils
{
	private static final String KEY_NAME_REGEX = "^[A-Za-z0-9]{1,40}$";
	
	private CommonUtils()
	{
		super();
	}
	
    /**
     * Method to assess whether the LunaSP is logged into its partition
     * @return boolean denoting logged in status
     */
	public static boolean isPartitionLoggedIn()
    {
        boolean rc;
        LunaTokenManager ltm;
        
        rc = false;
        ltm = null;
        
        // Get instance of LunaTokenManager
        ltm = LunaTokenManager.getInstance();
        
        // Is partition logged in?
        if(ltm.isLoggedIn() == true)
        {
            // Partition is logged in
            rc = true;
        }
        else
        {
            // Partition is not logged in
            rc = false;
        }
        
        return rc;
    }
	
	/**
     * Method to determine whether a String is hex encoded
	 * @param hexEncodedString The String to verify
	 * @return boolean denoting the hex encoded status of the String
	 */
	public static boolean isHexEncoded(String hexEncodedString)
	{
		boolean rc;
		
		rc = false;
		
		try
		{
			Hex.decodeHex(hexEncodedString.toCharArray());
			
			rc = true;
		} 
		catch(DecoderException de)
		{
		    //No action required - allow code to return false
		}
		
		return rc;
	}
	
	/**
     * Method to generate an RSA key pair
	 * @param keySize The key length to generate
	 * @param publicExponent The exponent to use
	 * @return The generated {@link KeyPair}
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static KeyPair generateRsaKeyPair(int keySize, BigInteger publicExponent) throws NoSuchAlgorithmException,
	    NoSuchProviderException, InvalidAlgorithmParameterException
	{
	    KeyPair kp;
	    KeyPairGenerator kpg;
	    RSAKeyGenParameterSpec kgps;
	
	    kp = null;
	    kpg = null;
	    kgps = null;
	
	    kpg = KeyPairGenerator.getInstance("RSA");
	    kgps = new RSAKeyGenParameterSpec(keySize, publicExponent);
	    kpg.initialize(kgps);
	    kp = kpg.generateKeyPair();
	
	    return kp;
	}
	
	/**
     * Method to ensure that a key name fits the required parameters
	 * @param keyName The key name to check
	 * @return boolean denoting validity
	 */
	public static boolean validateKeyName(String keyName)
	{
		boolean rc;
		
		rc = false;
		
		// Validate key name against a regular expression
		if(keyName.matches(KEY_NAME_REGEX) == true)
		{
            // Key name did not match regular expression
			rc = true;
			
			return rc;
		}
		
		return rc;
	}	
}