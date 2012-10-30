// $Id: KeyManagement/src/com/safenetinc/viewpin/utils/ListKeyStoreEntries.java 1.10 2009/01/22 16:50:56GMT+05:30 Malik, Pratibha (Pmalik) Exp  $
package com.safenetinc.viewpin.utils;

import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.codec.binary.Hex;
import com.safenetinc.viewpin.utils.CommonUtils;
import com.safenetinc.Common;

/**
 * Class to list the contents of the LunaSP partition
 * @author Stuart Horler
 *
 */
public class ListKeyStoreEntries
{
    /**
     * Constructor - handles command line arguments and lists the
     * contents of the partition
     * @param args command line arguments from the user
     */
	private static final String APPLICATION_NAME = "ListKeyStoreEntries";
	
    public ListKeyStoreEntries(String[] args)
    {
        super();
        
		if(args.length !=0)
		{
			Options commandLineOptions = null;
			commandLineOptions = new Options();
			
			HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp(APPLICATION_NAME,commandLineOptions, true);
            return;
		}	
		
        try
        {
            processCommandLine(args);
            
            if(listKeyStoreEntries()==false)
			{
				System.out.println("List Key Store Entries failed.");	
			}
			else
			{
				System.out.println("List Key Store Entries successful.");
			}
        }
        catch(ParseException pe)
        {
            return;
        }
    }
    
    private boolean listKeyStoreEntries()
    {
        KeyStore ks;
        Enumeration<String> entryAliases;
        String nextEntryAlias;
        Key nextKeyEntry;
        Certificate nextCertificateEntry;
        X509Certificate nextX509Certificate;
        Certificate[] nextChain;
        
        ks = null;
        entryAliases = null;
        nextEntryAlias = null;
        nextKeyEntry = null;
        nextCertificateEntry = null;
        nextX509Certificate = null;
        nextChain = null;
        
        try
        {
            ks = KeyStore.getInstance("Luna", "LunaJCAProvider");
            ks.load(null, null);
        
            entryAliases = ks.aliases();
            
            while(entryAliases.hasMoreElements() == true)
            {
				
                nextEntryAlias = entryAliases.nextElement();
       				
				try
				{
					 if(ks.isKeyEntry(nextEntryAlias) == true)
					{
						

						nextKeyEntry = ks.getKey(nextEntryAlias, null);
				   
						System.out.println(nextEntryAlias + " : " + nextKeyEntry.getAlgorithm());
						
						nextChain = ks.getCertificateChain(nextEntryAlias);
						
						if(nextChain == null)
						{
							continue;
						}
						
						for(int i = 0; i < nextChain.length; i++)
						{
							if(nextChain[i] instanceof X509Certificate == true)
							{
							
								nextX509Certificate = (X509Certificate)nextChain[i];
								System.out.println(nextEntryAlias);
								System.out.println("\t" + new String(Hex.encodeHex(nextX509Certificate.getSerialNumber().toByteArray())));
								System.out.println("\t" + nextX509Certificate.getSubjectDN().getName());
								System.out.println("\t" + nextX509Certificate.getIssuerDN().getName());
								System.out.println("\t" + nextX509Certificate.getNotBefore());
								System.out.println("\t" + nextX509Certificate.getNotAfter());
							}
						}
					}
					else if(ks.isCertificateEntry(nextEntryAlias) == true)
					{	
						
						
						nextCertificateEntry = ks.getCertificate(nextEntryAlias);

						
						if(nextCertificateEntry instanceof X509Certificate == true)
						{
							nextX509Certificate = (X509Certificate)nextCertificateEntry;
							
							System.out.println(nextEntryAlias);
							System.out.println("\t" + new String(Hex.encodeHex(nextX509Certificate.getSerialNumber().toByteArray())));
							System.out.println("\t" + nextX509Certificate.getSubjectDN().getName());
							System.out.println("\t" + nextX509Certificate.getIssuerDN().getName());
							System.out.println("\t" + nextX509Certificate.getNotBefore());
							System.out.println("\t" + nextX509Certificate.getNotAfter());
						}
						
					}
					
					
				}
				catch (Exception e)
				{
					 System.err.println(e.getMessage());
				}
			
              
            }
        }
        catch(RuntimeException re)
        {
            System.err.println(re.getMessage());
			return false;
        }
        catch(Exception e)
        {
            System.err.println(e.getMessage());
			return false;
        }
		
		return true;
    }
    
    private void processCommandLine(String[] args) throws ParseException
    {
        Options commandLineOptions;
        CommandLineParser clp;
        
        commandLineOptions = null;
        clp = null;
        
        commandLineOptions = new Options();
        
        clp = new PosixParser();
		
		     
        try
        {
            clp.parse(commandLineOptions, args);
        }
        catch(ParseException pe)
        {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp(APPLICATION_NAME, commandLineOptions, true);
            System.err.println(pe.getMessage());
            
            throw pe;
        }
		
	}
    
    /**
     * Simple main method - creates an instance of ListKeyStoreEntries passing
     * the command line arguments from the user
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
		new ListKeyStoreEntries(args);
		if(isLoggedIn==false)
		{
			Common.partition_logout();
		}
    }
}