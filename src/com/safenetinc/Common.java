/* first checkin changes */
package com.safenetinc;

import com.chrysalisits.crypto.LunaTokenManager;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import java.lang.Object;

import iaik.pkcs.pkcs11.wrapper.PKCS11Implementation;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_SESSION_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_SLOT_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_TOKEN_INFO;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Connector;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenInfo;

/**
 * Class to check Partition is logged in or not
 * @author Pratibha Malik
 */

public class Common {

	static long MofnSession = 0;
	
	public native long MofnAuthentication(long MofnSessionHandle);
	public native char[] GetPass();
	private static LunaTokenManager ltm;
	
	static 
	{
		try
		{
			System.load("/usr-xfiles/libMofNCJavaInterface.so");
		} 
		catch(UnsatisfiedLinkError eod) 
		{
			System.out.println("Found error while loading file : " + eod.getMessage());
		}
	}
	
    /**
     * Method to assess whether the LunaSP is logged into its partition
     * @return boolean denoting logged in status
     */
	public static boolean isPartitionLoggedIn()
    {
        boolean rc;
                
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
	
	public static long partitionAndMofnAuthentication(boolean isLogin)
    {
	   PKCS11 pkcsModule = null;
	   boolean rc;
       rc = false;
        
	   try
	   {
		  pkcsModule = PKCS11Connector.connectToPKCS11Module("/usr/lib/libCryptoki2.so");   
	   }
	   catch(IOException execp) 
	   {
			System.out.println("Partition login failed .Couldnt Initialize the Crypto Library ");
			return 1;
	   }
			
       try
	   {
			MofnSession = pkcsModule.C_OpenSession(1, PKCS11Constants.CKF_SERIAL_SESSION , null, null);
	   }
	   catch(PKCS11Exception p)
	   {
			System.out.println("Partition login failed.Couldnt open session : " + p.getMessage());
			return 1;
	   }
	   
       if(isLogin==false)
	   {
		    try
			{
				String password = null;
				Common com = new Common();
				password = new String(com.GetPass());
				System.out.println("Please check the PED to see if a login is required using Black key.");
				ltm.Login(password.trim());
				
				
		   }
		   catch(Exception p)
		   {
				System.out.println("Partition login failed.Couldnt login into Session.");
				return 1;
		   }
		  
		   System.out.println("Provide MOfN authentication, use Green Keys");
		      
           Common mofn_auth = new Common();
		   long retCode=mofn_auth.MofnAuthentication(MofnSession);
           if(retCode != 0)
           {
             System.out.println("MofN Authentication Failed");
			 try 
			 {
				//logout(MofnSession);
				ltm.Logout();
				close_session(MofnSession);
				pkcsModule.C_Finalize(null);
			}
			catch(PKCS11Exception pexe)
			{
				return 1;
			}
			return 1;
          }
           
		  return 0;
       }
	   else if(isLogin==true)
	   {
	      System.out.println("Partition is already logged in.");
		  System.out.println("Provide MOfN authentication, use Green Keys");
		      
          Common mofn_auth = new Common();
		  long retCode=mofn_auth.MofnAuthentication(MofnSession);
          if(retCode != 0)
          {
            System.out.println("MofN Authentication Failed");
			return 1;
          }
	   }
	   return 0;
   }
   
   /**
         *   API for Closing the Session
         */ 
   public static int close_session(long MofnSession) 
   {
       PKCS11 pkcsModule = null;
       try
       {
		   pkcsModule = PKCS11Connector.connectToPKCS11Module("/usr/lib/libCryptoki2.so");
	   }
       catch(IOException execp) 
       {
          System.out.println("Closing Session failed .Couldnt Initialize the Crypto Library ");
		  return 1;  
	   }
	   try
	   {
			pkcsModule.C_CloseSession(MofnSession);
	   }
	   catch(PKCS11Exception p)
       {
		  System.out.println("Closing Session failed : " + p.getMessage());
          return 1;
       }
	   return 0;   
   }
   
   /**
         *   API for Logout the Session
         */ 
   
   public static int logout(long MofnSession)
   {
       PKCS11 pkcsModule = null;
       try
       {
		   pkcsModule = PKCS11Connector.connectToPKCS11Module("/usr/lib/libCryptoki2.so");
	   }
       catch(IOException execp) 
       {
          System.out.println("Partition logout failed .Couldnt Initialize the Crypto Library ");
		  return 1;  
	   }
	   
       try
       {
          pkcsModule.C_Logout(MofnSession);
       }
       catch(PKCS11Exception p)
       {
		  System.out.println("Partition logout failed : " + p.getMessage());
          return 1;
       }
	   
	   return 0;
   }
	
   public static void partition_logout()
   {
		PKCS11 pkcsModule = null;
		ltm.Logout();
		close_session(MofnSession);
		try
		{
		   pkcsModule = PKCS11Connector.connectToPKCS11Module("/usr/lib/libCryptoki2.so");
		}
		catch(IOException execp) 
		{
          System.out.println("Partition logout failed .Couldnt Initialize the Crypto Library ");
		  return;  
		}
		try 
	    {
			pkcsModule.C_Finalize(null);
		}
		catch(PKCS11Exception pexe)
		{
			System.out.println("Logout Exception: " + pexe.getMessage());
		}
   }

}
