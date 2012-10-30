// $Id: KeyManagement/src/com/safenetinc/viewpin/utils/ImportCertificate.java 1.6 2009/01/21 12:50:52GMT+05:30 Gupta, Rahul (rgupta4) Exp  $
package com.safenetinc.viewpin.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Hex;
import com.safenetinc.viewpin.utils.CommonUtils;
import com.safenetinc.Common;
/**
 * Class to handle importing a certificate into the LunaSP
 * @author Stuart Horler
 *
 */
public class ImportCertificate
{
    private static final String IMPORT_AREA_DIRECTORY = "/usr-files";

    private String certificateFilename   = null;
	
	private static final String APPLICATION_NAME = "ImportCertificate";

    /**
     * Handles parsing command line arguments and the subsequent certificate import.
     * @param args Standard command line arguments
     * @throws Exception
     */
    public ImportCertificate(String[] args) throws Exception
    {
        super();

        try
        {
            processCommandLine(args);

            importCertificate();
        }
        catch(ParseException pe)
        {
            //No action required
        }
    }

    private void importCertificate() throws Exception
    {
        File f;
        FileInputStream fis;
        X509Certificate[] certificateChain;
        Certificate endEntityCertificate;
        String endEntityCertificateSubjectKeyIdentifier;
        KeyStore ks;
        Key privateKey;
        
        f = null;
        fis = null;
        certificateChain = null;
        endEntityCertificate = null;
        endEntityCertificateSubjectKeyIdentifier = null;
        ks = null;
        privateKey = null;
        
        f = new File(getCertificateFilename());

        // Ensure we can read file containing certificate
        if(f.canRead() == false)
        {
            System.out.println("certificate file " + f.getName() + " not found");

            return;
        }
        
        try
        {
            fis = new FileInputStream(f);

            // Parse X509 certificate chain
            certificateChain = parseX509CertificateChain(fis);
            
        }
        finally
        {
            if (fis != null)
            {
                fis.close();
            }
        }
        
        // Ensure certificate chain is not empty
        if(certificateChain.length < 1)
        {
            // Certificate chain is empty
            System.out.println("certificate chain is empty");
            
            return;
        }
        
        // Get end entity certificate
        endEntityCertificate = certificateChain[0];
        
        // Generate end entity certificate subject key identifier
        endEntityCertificateSubjectKeyIdentifier = generateSubjectKeyIdentifier(endEntityCertificate);
        
        // Initialiase key store
        ks = KeyStore.getInstance("Luna", "LunaJCAProvider");
        ks.load(null, null);
       
        // Is this a certificate request reply?
        if(ks.isKeyEntry(endEntityCertificateSubjectKeyIdentifier) == true)
        {
            // This is a certificate request reply, get private key
            privateKey = ks.getKey(endEntityCertificateSubjectKeyIdentifier, null);
            
            // Update certificate chain associated with this private key
            ks.setKeyEntry(endEntityCertificateSubjectKeyIdentifier, privateKey, null, certificateChain);
            
            System.out.println("imported certificate request reply " + endEntityCertificateSubjectKeyIdentifier + " OK");
        }
        else
        {
            // No associated private key, treat as trusted certificate
            ks.setCertificateEntry(endEntityCertificateSubjectKeyIdentifier, endEntityCertificate);
        
            System.out.println("imported trusted certificate " + endEntityCertificateSubjectKeyIdentifier + " OK");
        }
    }
    
    @SuppressWarnings("unchecked")
    private X509Certificate[] parseX509CertificateChain(InputStream is) throws CertificateException
    {
        X509Certificate[] certificateChain;
        CertificateFactory cf;
        Collection certificateChainCollection;
        Iterator chainIterator;
        
        certificateChain = null;
        cf = null;
        certificateChainCollection = null;
        chainIterator = null;
        
        // Instantiate X509 certificate factory
        cf = CertificateFactory.getInstance("X509");

        // Parse X509 certificate chain
        certificateChainCollection = cf.generateCertificates(is);
  
        // Instantiate array to hold X509 certificate chain
        certificateChain = new X509Certificate[certificateChainCollection.size()];
        
        // Get iterator over X509 certificate chain
        chainIterator = certificateChainCollection.iterator();
        
        // Work through each X509 certificate in certificate chain collection
        for(int i = 0; i < certificateChain.length; i++)
        {
            // Copy next X509 certificate from collection to array
            certificateChain[i] = (X509Certificate)chainIterator.next();
        }
        
        return certificateChain;
    }
    
    private String generateSubjectKeyIdentifier(Certificate certificate) throws IOException
    {
        String subjectKeyIdentifier;
        ASN1InputStream is;
        SubjectPublicKeyInfo spki;
        SubjectKeyIdentifier ski;

        subjectKeyIdentifier = null;
        is = null;
        spki = null;
        ski = null;
        
        try
        {
            is = new ASN1InputStream(certificate.getPublicKey().getEncoded());
        
            spki = new SubjectPublicKeyInfo((ASN1Sequence)is.readObject());
            ski = new SubjectKeyIdentifier(spki);
        }
        finally
        {
            if(is != null)
            {
                is.close();
            }
        }

        subjectKeyIdentifier = new String(Hex.encode(ski.getKeyIdentifier()));
        
        return subjectKeyIdentifier;
    }

    private void processCommandLine (String[] args) throws ParseException
    {
        Option certificateFilenameOption;
        Options commandLineOptions;
        CommandLineParser clp;
        CommandLine cl;

        certificateFilenameOption = null;
        commandLineOptions = null;
        clp = null;
        cl = null;

        certificateFilenameOption = new Option("f", "file", true, "file name containing certificate to be imported");
        certificateFilenameOption.setRequired(true);
        certificateFilenameOption.setArgs(1);
        certificateFilenameOption.setOptionalArg(false);
        certificateFilenameOption.setArgName("filename");

        commandLineOptions = new Options();
        commandLineOptions.addOption(certificateFilenameOption);

        clp = new PosixParser();

        try
        {
            cl = clp.parse(commandLineOptions, args);

            setCertificateFilename(IMPORT_AREA_DIRECTORY + "/" + cl.getOptionValue('f'));
        }
        catch (ParseException pe)
        {
            HelpFormatter formatter = new HelpFormatter();

            formatter.printHelp(APPLICATION_NAME, commandLineOptions, true);

            throw pe;
        }
    }

    /**
     * @return The certificate filename
     */
    public String getCertificateFilename ()
    {
        return this.certificateFilename;
    }

    private void setCertificateFilename (String certificateFilename)
    {
        this.certificateFilename = certificateFilename;
    }

    /**
     * Simply invokes the constructor of ImportCertificate passing the command line arguments
     * @param args The arguments from the User
     * @throws Exception
     */
    public static void main (String[] args) throws Exception
    {
		boolean isLoggedIn = Common.isPartitionLoggedIn();
		if(Common.partitionAndMofnAuthentication(isLoggedIn)!=0)
		{
		  System.out.println("Authentication Failed");
		  return;
		}
        new ImportCertificate(args);
		if(isLoggedIn==false)
		{
			Common.partition_logout();
		}
    }
}