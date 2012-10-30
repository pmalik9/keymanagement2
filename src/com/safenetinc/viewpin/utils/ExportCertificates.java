// $Id: KeyManagement/src/com/safenetinc/viewpin/utils/ExportCertificates.java 1.7 2009/01/21 12:50:53GMT+05:30 Gupta, Rahul (rgupta4) Exp  $
package com.safenetinc.viewpin.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import com.safenetinc.viewpin.utils.CommonUtils;
import com.safenetinc.Common;

/**
 * Class to handle exporting certificates from the LunaSP keystore.
 * Dumps all certificates to files on the LunaSP filesystem
 * @author Stuart Horler
 *
 *
 */
public class ExportCertificates 
{
	private static final String EXPORT_AREA_DIRECTORY = "/usr-files";
	
	private static final String APPLICATION_NAME = "ExportCertificates";
	
    /**
     * Initialise the class
     * @param args The command line arguments from the user
     * @throws Exception Thrown if we are unable to export
     */
	public ExportCertificates(String[] args) throws Exception
    {
        super();

        try
        {
           if (false == processCommandLine(args))
           {
				 System.out.println("Export Certificates failed");
			     return;
		    } 

            exportCertificates();
        }
        catch(ParseException pe)
        {
            //No action required
        }
    }
	
	private void exportCertificates() throws Exception
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
                            
                            exportCertificate(nextX509Certificate);
                            
                        }
                    }
                }
                else
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
                        
                        exportCertificate(nextX509Certificate);
                    }
                }
            }
        }
        catch(RuntimeException re)
        {
            System.err.println(re.getMessage());
            re.printStackTrace();
        }
        catch(Exception e)
        {
            System.err.println(e.getMessage());
            e.printStackTrace();
        }
    }
	
	private void exportCertificate(X509Certificate certificate) throws IOException, CertificateEncodingException
	{
		SubjectPublicKeyInfo spki;
        SubjectKeyIdentifier ski;
        String certificateAlias;
        org.bouncycastle.asn1.ASN1InputStream asn1InputStream;
        
        spki = null;
        ski =  null;
        certificateAlias = null;
        asn1InputStream = null;
        
        try
        {
            asn1InputStream = new org.bouncycastle.asn1.ASN1InputStream(certificate.getPublicKey().getEncoded());
            org.bouncycastle.asn1.ASN1Sequence sequence = (org.bouncycastle.asn1.ASN1Sequence) asn1InputStream.readObject();
            spki = new SubjectPublicKeyInfo(sequence);
            ski = new SubjectKeyIdentifier(spki);
        }
        finally
        {
            if (asn1InputStream != null)
                asn1InputStream.close();
        }
        

	    certificateAlias = new String(Hex.encodeHex(ski.getKeyIdentifier()));
	    
	    File f = new File(EXPORT_AREA_DIRECTORY + "/" + certificateAlias + ".cer");
	    
	    FileOutputStream fos = new FileOutputStream(f);
	    fos.write(certificate.getEncoded());
        fos.close();
        
        System.out.println("exported certificate " + certificateAlias + ".cer OK");
	}

	private boolean processCommandLine(String[] args) throws ParseException
    {
        Options commandLineOptions;
        CommandLineParser clp;
       
        commandLineOptions = null;
        clp = null;
       
        commandLineOptions = new Options();
    
        clp = new PosixParser();

		if (args.length >=1)
		{
			System.out.println("No argument required");
			return false;
		}
        try
        {
            clp.parse(commandLineOptions, args);
        }
        catch(ParseException pe)
        {
            HelpFormatter formatter = new HelpFormatter();

            formatter.printHelp(APPLICATION_NAME, commandLineOptions, true);

			System.err.println("Parsing of arguments failed");
			return false;
        }

		return true;
    }

    /**
     * Simple main method, simply creates a new instance of ExportCertificates passing the
     * command line arguments
     * @param args Standard command line arguments
     * @throws Exception
     */
	public static void main(String[] args) throws Exception
    {
	    boolean isLoggedIn = Common.isPartitionLoggedIn();
		if(Common.partitionAndMofnAuthentication(isLoggedIn)!=0)
		{
		  System.out.println("Authentication Failed");
		  return;
		}

        new ExportCertificates(args);
		if(isLoggedIn==false)
		{
			Common.partition_logout();
		}
    }
}
