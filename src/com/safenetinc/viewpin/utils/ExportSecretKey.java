package com.safenetinc.viewpin.utils;


import java.io.File;
import java.io.FileInputStream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.codec.binary.Hex;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.Key;
import com.safenetinc.viewpin.utils.CommonUtils;
import com.safenetinc.Common;

/**
 * 
 * @author Pmalik
 *  class to wrap the key and save it to the mentioned file
 *
 */
public class ExportSecretKey {
	
	private  String wrappingCertificateName 				= null;
	
	private  String wrappingTransformation 					= null;
	
	private  String secretKeyName		   					= null;
	
	private  String keystore				   				= null;
	
	private  String password				   				= null;
	
	private  String keystoreFilePath		   				= null;
	
	private  String wrappedFilePath		  					= null;
	
	private  KeyStore ks			   						= null;
	
	private  final String wrappingCertificateNameOpt		= "cert";
	
	private  final String wrappingTransformationOpt			= "algo";
	
	private  final String secretKeyNameOpt					= "secKey";
	
	private  final String keyStoreOpt						= "ks";
	
	private  final String passwordOpt						= "pw";
	
	private  final String keystoreFilePathOpt				= "ksFile";
	
	private  final String WrappedFilePathOpt				= "wrapFile";
	
	private  final String APPLICATION_NAME               	= "ExportSecretKey";

	static boolean  isLoggedIn								= false;

	static boolean  isLuna									= false;
    
	 
	public ExportSecretKey(String[] args)
	{

		try{
			 
			if(false == processCommandLine(args))
        	{
        	   		return;
        	}
        	
			if(this.getKeystore() != null)
			{
				ks = KeyStore.getInstance(this.getKeystore());
						
			    if(0 == this.getKeystore().compareToIgnoreCase("luna") )
			    {
			    	ks.load(null, null);
					//setting is Luna to true so as to logout from main after exporting key
					isLuna = true;
		
					isLoggedIn = Common.isPartitionLoggedIn();
				    if(Common.partitionAndMofnAuthentication(isLoggedIn)!=0)
					{
					  System.out.println("Authentication Failed");
					  return;
					}
				}	
				else
				{
					if((this.getPassword() != null) && (this.getKeystoreFilePath() != null))
			    	ks.load(new FileInputStream(this.getKeystoreFilePath()), this.getPassword().toCharArray());
				}
			}
			else
        	{
        		System.out.println("Invalid Keystore");
        		return;
			
        	}
			
			if (false == exportSecretKey())
			 {
            	System.out.println("ExportSecretKey Failed");
        		return;
            }
		}
		catch(ParseException pe)
        {
			System.out.println("Could not parse input elements");
        	System.out.println("ExportSecretKey Failed");
    		return;
        }
		catch(Exception pe)
        {
        	System.out.println("ExportSecretKey Failed");
    		return;
        }
		
	}
	
	
	private boolean exportSecretKey() throws Exception
	{
		Certificate wrappingCertificate =null;
		String wrappingTransformation=null;
		Key secretKey=null;
	   
	    byte[] unencodedWrappedSecretKey=null; 
		String base64EncodedWrappedSecretKey=null;
			
		try
		{
		wrappingCertificate=ks.getCertificate(this.getWrappingCertificateName());
		wrappingTransformation=new String(this.getWrappingTransformation());
		
		System.out.println("Getting key= "+ this.getSecretKeyName());
		
		//get the key
		
		   if((this.getKeystore() != null )&& 
		     (0 == this.getKeystore().compareToIgnoreCase("luna")))
			   	secretKey=ks.getKey(this.getSecretKeyName(), null);
		   else
		   {
			   if(this.getPassword() != null)
			   secretKey=ks.getKey(this.getSecretKeyName(),this.getPassword().toCharArray());
		   }

		//wrap the key		
		try
		{
			unencodedWrappedSecretKey=WrapUnwrap.wrapKey(wrappingCertificate, wrappingTransformation,secretKey);
		}
		catch (NoSuchPaddingException e)
		{
			System.out.println("No such Padding ");
			return false;
		}
		catch (NoSuchAlgorithmException e)
		{
			System.out.println("No such algorithm ");
			return false;
		}
		catch (InvalidKeyException e)
		{
			System.out.println("Invalid Key");
			return false;
		}
		catch (IllegalStateException e)
		{
			System.out.println("Illegal State");
			return false;
		}
		catch (IllegalBlockSizeException e)
		{
			System.out.println("Illegal Block Size ");
			return false;
		}
	
		
		System.out.println("wrapped key");
		
		base64EncodedWrappedSecretKey=new String(Hex.encodeHex(unencodedWrappedSecretKey));
		if(this.getWrappedFilePath() != null)
		{
			BufferedWriter out = new BufferedWriter(new FileWriter(this.getWrappedFilePath()));
			out.write(base64EncodedWrappedSecretKey.toString());
			out.close();
		}
		
		System.out.println("Export Key Successful");
		return true;
		}
		 catch(RuntimeException re)
        {
			 System.out.println("Could not export Secret Key");
              return false;
        }
        catch(Exception re)
        {
			 System.out.println("Could not export Secret Key");
              return false;
        }
	}
	
	 

	
	/**
     * @return The wrapped key Certificate name
     */
    public String getWrappingCertificateName ()
    {
        return this.wrappingCertificateName;
    }

    private void setWrappingCertificateName (String wrappingCertificateName)
    {
    	this.wrappingCertificateName = wrappingCertificateName;
    }


	/**
     * @return The wrapping transformation
     */
    public String getWrappingTransformation()
    {
        return this.wrappingTransformation;
    }

    private  void setWrappingTransformation (String wrappingTransformation)
    {
    	this.wrappingTransformation = wrappingTransformation;
    }

    /**
     * @return The wrapping transformation
     */
    public String getSecretKeyName()
    {
        return this.secretKeyName;
    }

    private  void setSecretKeyName (String secretKeyName)
    {
    	this.secretKeyName = secretKeyName;
    }
    
    /**
     * @return The Keystore 
     */
    public String getKeystore()
    {
        return this.keystore;
    }

    private  void setKeystore (String keystore)
    {
    	this.keystore = keystore;
    }
    
    /**
     * @return The Password 
     */
    public String getPassword()
    {
        return this.password;
    }

    private  void setPassword (String password)
    {
    	this.password = password;
    }
    
    /**
     * @return The Keystore File Path 
     */
    public String getKeystoreFilePath()
    {
        return this.keystoreFilePath;
    }

    private  void setKeystoreFilePath (String KeystoreFilePath)
    {
    	this.keystoreFilePath = KeystoreFilePath;
    }
    
    
    
    /**
     * @return The Wrapped File Path 
     */
    public String getWrappedFilePath()
    {
        return this.wrappedFilePath;
    }

    private  void setWrappedFilePath (String wrappedFilePath)
    {
    	this.wrappedFilePath = wrappedFilePath;
    }
    
    private boolean processCommandLine (String[] args) 
    {
    	  // parse the command line arguments
        final Options options = new Options();

        OptionBuilder.withArgName(wrappingCertificateNameOpt);
        OptionBuilder.hasArg();
        OptionBuilder.isRequired();
        OptionBuilder.withDescription("Name of the wrapping certificate(alias name)");
        final Option wrappingCertificateNameOption = OptionBuilder.create(wrappingCertificateNameOpt);
        
        OptionBuilder.withArgName(wrappingTransformationOpt);
        OptionBuilder.hasArg();
        OptionBuilder.isRequired();
        OptionBuilder.withDescription("Wrapping Algorithim");
        final Option wrappingTransformationOption = OptionBuilder.create(wrappingTransformationOpt);

        OptionBuilder.withArgName(secretKeyNameOpt);
        OptionBuilder.hasArg();
        OptionBuilder.isRequired();
        OptionBuilder.withDescription("Name of secretKey to be exported (alias name)");
        final Option secretKeyNameOption = OptionBuilder.create(secretKeyNameOpt);
        
        OptionBuilder.withArgName(keyStoreOpt);
        OptionBuilder.hasArg();
        OptionBuilder.isRequired();
        OptionBuilder.withDescription("Keystore Type");
        final Option keyStoreOption = OptionBuilder.create(keyStoreOpt);
        
        OptionBuilder.withArgName(passwordOpt);
        OptionBuilder.hasArg();
         OptionBuilder.withDescription("Keystore Password");
        final Option passwordOption = OptionBuilder.create(passwordOpt);
        
        OptionBuilder.withArgName(keystoreFilePathOpt);
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("Keystore File Path");
        final Option keystoreFilePathOption = OptionBuilder.create(keystoreFilePathOpt);

        OptionBuilder.withArgName(WrappedFilePathOpt);
        OptionBuilder.hasArg();
        OptionBuilder.isRequired();
        OptionBuilder.withDescription("Wrapped File Path");
        final Option WrappedFilePathOption = OptionBuilder.create(WrappedFilePathOpt);
        
    
        options.addOption(wrappingCertificateNameOption);
        options.addOption(secretKeyNameOption);
        options.addOption(wrappingTransformationOption);
        options.addOption(keyStoreOption);
        options.addOption(passwordOption);
        options.addOption(keystoreFilePathOption);
        options.addOption(WrappedFilePathOption);
        
        final CommandLineParser parser = new GnuParser();
        CommandLine cmd = null;
      
        	        
        
        try
        {
        	cmd = parser.parse(options, args);
        	 if((null == cmd.getOptionValue(wrappingCertificateNameOpt)) ||
                 (null == cmd.getOptionValue(wrappingTransformationOpt)) ||
                 (null == cmd.getOptionValue(secretKeyNameOpt)) ||
                 (null == cmd.getOptionValue(keyStoreOpt))||
                 (null == cmd.getOptionValue(WrappedFilePathOpt)) 
                )
              {
                  	System.err.println("Null values not allowed");
					return false;
              }
              else
              {
            	  
            	 setWrappingCertificateName(cmd.getOptionValue(wrappingCertificateNameOpt));
            	
  	            
  	             setWrappingTransformation(cmd.getOptionValue(wrappingTransformationOpt));
  	           
  	            
  	             setSecretKeyName(cmd.getOptionValue(secretKeyNameOpt));
  	          
  	            
  	             setKeystore(cmd.getOptionValue(keyStoreOpt));
  	           
  	         	 if(null != cmd.getOptionValue(passwordOpt))
  	         		 setPassword(cmd.getOptionValue(passwordOpt));
  	            
  	             if(null != cmd.getOptionValue(keystoreFilePathOpt))
  	            	setKeystoreFilePath(cmd.getOptionValue(keystoreFilePathOpt));
  	            
  	             setWrappedFilePath(cmd.getOptionValue(WrappedFilePathOpt));
  	           
              }
           return true;
            
        }
        catch (ParseException pe)
        {

            final HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp(APPLICATION_NAME, options);
            return false;
        }
    }
    
	  /**
     * Simply invokes the constructor of ExportSecretKey passing the command line arguments
     * @param args The arguments from the User
     * @throws Exception
     */
    public static void main (String[] args) throws Exception
    {
	   	
        new ExportSecretKey(args);

		//logout only if its Luna
		if(isLuna == true)
		{
			if(isLoggedIn==false)
			{
				Common.partition_logout();
			}
		}
    }
}
