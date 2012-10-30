package com.safenetinc.viewpin.utils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.OptionBuilder;



import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.encoders.Hex;
import com.safenetinc.viewpin.utils.CommonUtils;
import com.safenetinc.Common;

import com.chrysalisits.cryptox.*; // Load LunaJCEProvider classes
import com.chrysalisits.crypto.*;  // Load LunaJCAProvider classes
//import org.apache.commons.codec.binary.Hex;

/**
 * @author Pmalik
 * class to unwrap the key and save it into the keystore
 */

public class ImportSecretKey {
	
    private  final String IMPORT_AREA_DIRECTORY 			= "/usr-files";

    private  String wrappedKeyFilename 						= null;
    
    private  String wrappingKeyName   						= null;
             
    private  String wrappingTransformation 					= null;
    
    private  String wrappedKeyType   		 				= null;
    
    private  String importedKeyName   						= null;
    
    private  String keystore								= null;
    
    private  String password								= null;
    
    private  String keystoreFilePath						= null;
    
    private  KeyStore ks							   	   	= null;

    private  final String APPLICATION_NAME                	= "ImportSecretKey";
    
    private  final String wrappedKeyFilenameOpt		  		= "wrapKeyFileName";
    
    private  final String importedKeyNameOpt       			= "keyName";
    
    private  final String wrappingKeyNameOpt        		= "wrappingKeyName";
    
    private  final String wrappingTransformationOpt   		= "algo";
    
    private  final String wrappedKeyTypeOpt       			= "keyType";
    
    private  final String keystoreOpt        				= "ks";
    
    private  final String passwordOpt       				= "pw";
    	
    private  final String keystoreFilePathOpt		       	= "ksFile";

	static boolean   isLoggedIn								= false;

	static boolean   isLuna									= false;
    
    /**
     * Handles parsing command line arguments and the subsequent secret key import.
     * @param args Standard command line arguments
     * @throws Exception
     */
    public ImportSecretKey(String[] args) throws Exception
    {
        super();

        try
        {
        	if(false == processCommandLine(args))
        	{
        		System.out.println("ImportSecretKey Failed");
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
            if (false == importSecretKey())
            {
            	System.out.println("ImportSecretKey Failed");
        		return;
            }
            	
        }
        catch(ParseException pe)
        {
			System.out.println("Could not parse input elements");
        	System.out.println("ImportSecretKey Failed");
    		return;
        }
		catch(Exception pe)
        {
        	System.out.println("ImportSecretKey Failed");
    		return;
        }
    }
    
    private boolean importSecretKey() throws Exception
    {
        File f;
        byte[]byteArrWrappedKey;
        byte[] wrappedKey;
        PrivateKey wrappingKey;
        
        Key unwrappedSecretKey=null;
        Key secretKey=null;
        f = null;
        wrappingKey = null;
        wrappedKey=null;
        
        byteArrWrappedKey=null;
        String base64EncodedWrappedSecretKey=null;
		
        
        try
        {
            BufferedReader br=new BufferedReader(new FileReader(this.getWrappedKeyFilename()));
            String keyfromfile = null;
			String readLine = null;
			readLine = br.readLine();
            
            if(readLine != null)
            {
            	keyfromfile=readLine.trim();
            }
        	
            if(keyfromfile != null)
        	wrappedKey=Hex.decode(keyfromfile.getBytes());
        	         
          //get the private key from the keystore

			if(this.getWrappingKeyName() != null)
			{
            	if(0 == this.getKeystore().compareToIgnoreCase("luna") )
        			wrappingKey= (PrivateKey)ks.getKey(this.getWrappingKeyName(),null);
        		else
				{
				    if(this.getPassword() != null)
        			wrappingKey= (PrivateKey)ks.getKey(this.getWrappingKeyName(),this.getPassword().toCharArray());
				}
            }
        	if(null == wrappingKey)
        	{
        		if(this.getKeystore() != null)
        			System.out.println(this.getWrappingKeyName() + " not found in " + this.getKeystore() );
        		return false;
        	}
			else 
				System.out.println("Found Key" + this.getWrappingKeyName() );
        	// unwrap the key
			try
			{
				if(this.getWrappedKeyType() != null)
				unwrappedSecretKey=WrapUnwrap.unwrapKey(wrappedKey,this.getWrappingTransformation(),wrappingKey,this.getWrappedKeyType());
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
      
                     
            //set the key into the keystore file           
            if((this.getKeystore() != null) &&
            	(0 == this.getKeystore().compareToIgnoreCase("luna"))
				)
            {
            	ks.setKeyEntry(this.getImportedKeyName(), unwrappedSecretKey, null, (java.security.cert.Certificate[]) null);
            }
            else
            {
            	if(this.getPassword()!= null)
            	ks.setKeyEntry(this.getImportedKeyName(), unwrappedSecretKey, this.getPassword().toCharArray(), (java.security.cert.Certificate[]) null);
            }            
            
            
            
         // Save the new keystore contents
            if((this.getKeystore() != null)&&
            	(0 != this.getKeystore().compareToIgnoreCase("luna"))
				)
            {
				 if(this.getKeystoreFilePath() != null)
				 {
					FileOutputStream out = new FileOutputStream(new File(this.getKeystoreFilePath()));
					ks.store(out, this.getPassword().toCharArray());
					out.close();
				 }
            }

            System.out.println("Keystore now has " + ks.size() + " objects");
          
            if(this.getImportedKeyName() != null)
            {
            	System.out.println("\ngetImportedKeyName: " + this.getImportedKeyName());
            	System.out.println("Key was made persistant on " + ks.getCreationDate(this.getImportedKeyName()));
            }
            
                        
        }
		 catch(RuntimeException re)
        {
			 System.out.println("Could not import Secret Key");
              return false;
        }
        catch(Exception re)
        {
			 System.out.println("Could not import Secret Key");
              return false;
        }
       
        
        return true;   
    }
    
     
    /**
     * @return The wrapped key filename
     */
    public String getWrappedKeyFilename ()
    {
        return this.wrappedKeyFilename;
    }

    private  void setWrappedKeyFilename (String wrappedKeyFilename)
    {
    	this.wrappedKeyFilename = wrappedKeyFilename;
    }

    /**
     * @return The wrapped key Certificate name
     */
    public String getWrappingKeyName ()
    {
        return this.wrappingKeyName;
    }

    private  void setWrappingKeyName (String wrappingKeyName)
    {
    	this.wrappingKeyName = wrappingKeyName;
    }

    public String getImportedKeyName ()
    {
        return this.importedKeyName;
    }

    private  void setImportedKeyName (String importedKeyName)
    {
    	this.importedKeyName = importedKeyName;
    }

    /**
     * @return The wrapping transformation 
     */
    public String getWrappingTransformation ()
    {
    	return this.wrappingTransformation;
    }

    private  void setWrappingTransformation (String wrappingTransformation)
    {
    	this.wrappingTransformation = wrappingTransformation;
    }

    /**
     * @return The wrapped key type 
     */
    public String getWrappedKeyType ()
    {
        return this.wrappedKeyType;
    }

    private  void setWrappedKeyType (String wrappedKeyType)
    {
    	this.wrappedKeyType = wrappedKeyType;
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

    private void setPassword (String password)
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
    
    private boolean  processCommandLine (String[] args)
    {
    	   // parse the command line arguments
        final Options options = new Options();

        OptionBuilder.withArgName(wrappedKeyFilenameOpt);
        OptionBuilder.hasArg();
        OptionBuilder.isRequired();
        OptionBuilder.withDescription("file name containing wrraped secret key to be imported");
        final Option wrappedKeyFilenameOption = OptionBuilder.create(wrappedKeyFilenameOpt);

        OptionBuilder.withArgName(importedKeyNameOpt);
        OptionBuilder.hasArg();
        OptionBuilder.isRequired();
        OptionBuilder.withDescription("Name of Key to be imported (alias name)");
        final Option importedKeyNameOption = OptionBuilder.create(importedKeyNameOpt);
        
     
        OptionBuilder.withArgName(wrappingKeyNameOpt);
        OptionBuilder.hasArg();
        OptionBuilder.isRequired();
        OptionBuilder.withDescription("Wrapping certificate Identifier(alias name)");
        final Option wrappingKeyNameOption = OptionBuilder.create(wrappingKeyNameOpt);
        
        OptionBuilder.withArgName(wrappingTransformationOpt);
        OptionBuilder.hasArg();
        OptionBuilder.isRequired();
        OptionBuilder.withDescription("Wrapping Algorithim");
        final Option wrappingTransformationOption = OptionBuilder.create(wrappingTransformationOpt);
        
        
        OptionBuilder.withArgName(keystoreOpt);
        OptionBuilder.hasArg();
        OptionBuilder.isRequired();
        OptionBuilder.withDescription("Name of Keystore");
        final Option keystoreOption = OptionBuilder.create(keystoreOpt);

        OptionBuilder.withArgName(wrappedKeyTypeOpt);
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("Wrapped Key Type");
        final Option wrappedKeyTypeOption = OptionBuilder.create(wrappedKeyTypeOpt);
        
        
        OptionBuilder.withArgName(passwordOpt);
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("Keystore's Password");
        final Option passwordOption = OptionBuilder.create(passwordOpt);
        
        OptionBuilder.withArgName(keystoreFilePathOpt);
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("Keystore File Path");
        final Option keystoreFilePathOption = OptionBuilder.create(keystoreFilePathOpt);
           
        
        options.addOption(wrappedKeyFilenameOption);
        options.addOption(importedKeyNameOption);
        options.addOption(wrappingKeyNameOption);
        options.addOption(wrappingTransformationOption);
        options.addOption(keystoreOption);
        options.addOption(passwordOption);
        options.addOption(keystoreFilePathOption);
        options.addOption(wrappedKeyTypeOption);
        
        final CommandLineParser parser = new GnuParser();
        CommandLine cmd = null;
      
        try
        {
            cmd = parser.parse(options, args);
            
            if((null == cmd.getOptionValue(wrappedKeyFilenameOpt)) ||
               (null == cmd.getOptionValue(wrappingKeyNameOpt)) ||
               (null == cmd.getOptionValue(importedKeyNameOpt)) ||
               (null == cmd.getOptionValue(wrappingTransformationOpt))||
               (null == cmd.getOptionValue(wrappedKeyTypeOpt)) ||
               (null == cmd.getOptionValue(keystoreOpt))
               
             )
            {
            	
            	System.err.println("Null values not allowed");
				return false;
            }
            else
            {
             
	            setWrappedKeyFilename(cmd.getOptionValue(wrappedKeyFilenameOpt));
	            setWrappingKeyName(cmd.getOptionValue(wrappingKeyNameOpt));
	            setImportedKeyName(cmd.getOptionValue(importedKeyNameOpt));
	            setWrappingTransformation(cmd.getOptionValue(wrappingTransformationOpt));
	            setWrappedKeyType(cmd.getOptionValue(wrappedKeyTypeOpt));
	            setKeystore(cmd.getOptionValue(keystoreOpt));
	            
	            if(null != cmd.getOptionValue(passwordOpt))
	            	setPassword(cmd.getOptionValue(passwordOpt));
	            if(null != cmd.getOptionValue(keystoreFilePathOpt))
	            	setKeystoreFilePath(cmd.getOptionValue(keystoreFilePathOpt));
            }
            return true;
        }
        catch (final ParseException e)
        {
        	
            final HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp(APPLICATION_NAME, options);
            return false;
        }
    }
    
    /**
     * Simply invokes the constructor of ImportSecretKey passing the command line arguments
     * @param args The arguments from the User
     * @throws Exception
     */
    public static void main (String[] args) throws Exception
    {
        new ImportSecretKey(args);
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
