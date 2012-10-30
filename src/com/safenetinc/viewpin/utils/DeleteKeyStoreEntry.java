// $Id: KeyManagement/src/com/safenetinc/viewpin/utils/DeleteKeyStoreEntry.java 1.7 2009/01/22 16:23:32GMT+05:30 Gupta, Rahul (rgupta4) Exp  $
package com.safenetinc.viewpin.utils;

import java.security.KeyStore;
import java.security.KeyStoreException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import com.safenetinc.viewpin.utils.CommonUtils;
import com.safenetinc.Common;

/**
 * Class to handle deleting objects from the LunaSP keystore
 * @author Stuart Horler
 *
 */
public class DeleteKeyStoreEntry
{
    /**
     * Constructor
     * @param args The command line arguments passed by the user
     */
	private static final String APPLICATION_NAME = "DeleteKeyStoreEntry";
	
    public DeleteKeyStoreEntry(final String[] args)
    {
        super();
        
           
      
        try
        {
            processCommandLine(args);
        }
        catch(ParseException pe)
        {
            //No action required
        }
    }
    
    private void processCommandLine(String[] args) throws ParseException
    {
        Option keyStoreEntryNameOption;
        Options commandLineOptions;
        CommandLineParser clp;
        CommandLine cl;
        String keyStoreEntryName;
        
        keyStoreEntryNameOption = null;
        commandLineOptions = null;
        clp = null;
        cl = null;
        keyStoreEntryName = null;
        
        keyStoreEntryNameOption = new Option("n", "name of key store entry to be deleted");
        keyStoreEntryNameOption.setRequired(true);
        keyStoreEntryNameOption.setArgs(1);
        keyStoreEntryNameOption.setOptionalArg(false);
        keyStoreEntryNameOption.setArgName("name");
        
        commandLineOptions = new Options();
        commandLineOptions.addOption(keyStoreEntryNameOption);
        
        clp = new PosixParser();
        
        try
        {
            // Parse command line
            cl = clp.parse(commandLineOptions, args);
            
            // Get key store entry name option value
            keyStoreEntryName = cl.getOptionValue('n');
            
            // Validate key store entry name
            if(CommonUtils.validateKeyName(keyStoreEntryName) == false)
            {
                // Key store entry name is invalid
                System.out.println("invalid key store entry name");
                
                throw new ParseException("");
            }
        }
        catch(ParseException pe)
        {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp(APPLICATION_NAME, commandLineOptions, true);
            
            throw pe;
        }
        
        // Delete key store entry
        deleteKeyStoreEntry(keyStoreEntryName);
    }
    
    private void deleteKeyStoreEntry(String keyStoreEntryName)
    {
        KeyStore ks;
        
        ks = null;
        
        try 
        {
            // Load keystore
            ks = KeyStore.getInstance("Luna", "LunaJCAProvider");
            ks.load(null, null);
        } 
        catch(Exception e)
        {
            System.out.println("failed to load keystore");
    
            return;
        }
        
        try
        {
            // Ensure key store entry name alias exists before we attempt to delete
            if(ks.containsAlias(keyStoreEntryName) == false)
            {
                // Key store entry name alias does not exist
                System.out.println("key store entry " + keyStoreEntryName + " does not exist");
                
                return;
            }
        }
        catch(Exception e)
        {
            // Will never get here as key store has been successfully loaded
            System.err.println(e.getMessage());
            
            e.printStackTrace();
            
            return;
        }
            
        try
        {
            // Delete key store entry
            ks.deleteEntry(keyStoreEntryName);
        
            System.out.println("deleted key store entry " + keyStoreEntryName + " ok");
        }
        catch(KeyStoreException kse)
        {
            System.out.println("failed to delete key store entry " + keyStoreEntryName);
        }
    }
    
    /**
     * Main method - simply creates a new instance of DeleteKeyStoreEntry, passing the
     * command line arguments for processing
     * @param args Standard command line arguments
     */
    public static void main(String[] args)
    {
	    boolean isLoggedIn = Common.isPartitionLoggedIn();
		if(Common.partitionAndMofnAuthentication(isLoggedIn)!=0)
		{
		  System.out.println("Authentication Failed");
		  return;
		}
        new DeleteKeyStoreEntry(args);
		if(isLoggedIn==false)
		{
			Common.partition_logout();
		}
    }
}