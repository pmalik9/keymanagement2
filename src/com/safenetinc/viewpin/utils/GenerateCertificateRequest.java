// $Id: KeyManagement/src/com/safenetinc/viewpin/utils/GenerateCertificateRequest.java 1.11 2009/01/21 14:32:24GMT+05:30 Gupta, Rahul (rgupta4) Exp  $
package com.safenetinc.viewpin.utils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import com.safenetinc.viewpin.utils.CommonUtils;
import com.safenetinc.Common;

/**
 * Application to facilitate LunaSP users in creating certificate requests
 * 
 * @author Paul Hampton
 * 
 * 
 */
public class GenerateCertificateRequest
{
    @SuppressWarnings("unused")
    private GenerateCertificateRequest()
    {
        super();
    }

	public static final int MAX_KEYLEN = 4096;
	public static final int MIN_KEYLEN = 512;
	public static final String APPLICATION_NAME = "GenerateCertificateRequest";
    /**
     * Constructor, parses command line arguments and handles generating a csr
     * 
     * @param args Arguments from user
     */
    public GenerateCertificateRequest(String[] args)
    {
        super();

        try
        {
         
		  if (false == processCommandLine(args))
		  {
				 System.out.println("Generate Certificate Request failed");
			     return;
		  }
       
        }
        catch (Exception pe)
        {
			 System.out.println("Generate Certificate Request failed");
            return;
        }
    }

    private boolean generateCertificateRequest (int keyLength, X500Principal subject, int expireAfterDays)
    {
        KeyPair kp;
        X509V3CertificateGenerator certificateGenerator;
        BigInteger serialNumber;
        Date notBefore;
        Date notAfter;
        SubjectPublicKeyInfo spki;
        SubjectKeyIdentifier ski;
        X509Certificate selfSignedCertificate;
        KeyStore ks;
        String keyEntryAlias;
        PKCS10CertificationRequest certificateRequest;
        String encodedCertificateRequest;
        org.bouncycastle.asn1.ASN1InputStream asn1InputStream;

        kp = null;
        certificateGenerator = null;
        serialNumber = null;
        notBefore = null;
        notAfter = null;
        spki = null;
        ski = null;
        selfSignedCertificate = null;
        ks = null;
        keyEntryAlias = null;
        certificateRequest = null;
        encodedCertificateRequest = null;
        asn1InputStream = null;

        try
        {
            // Generate key pair
            kp = CommonUtils.generateRsaKeyPair(keyLength, RSAKeyGenParameterSpec.F4);

            // Instantiate version three X509 certificate generator
            certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.reset();

            // Generate random serial number
            serialNumber = generateSerialNumber();
            certificateGenerator.setSerialNumber(serialNumber);

            // Set subject and issuer distinguished names
            certificateGenerator.setIssuerDN(subject);
            certificateGenerator.setSubjectDN(subject);

            // Set certificate to expire after number of specified days from today
            notBefore = new Date();
            notAfter = addDays(notBefore, expireAfterDays);
            certificateGenerator.setNotBefore(notBefore);
            certificateGenerator.setNotAfter(notAfter);

            certificateGenerator.setPublicKey(kp.getPublic());
            certificateGenerator.setSignatureAlgorithm("SHA1withRSA");

            // Determine subject key identifier
            try
            {
                asn1InputStream = new org.bouncycastle.asn1.ASN1InputStream(kp.getPublic().getEncoded());
                org.bouncycastle.asn1.ASN1Sequence sequence = (org.bouncycastle.asn1.ASN1Sequence) asn1InputStream.readObject();
                spki = new SubjectPublicKeyInfo(sequence);
                ski = new SubjectKeyIdentifier(spki);
            }
            finally
            {
                if (asn1InputStream != null)
                    asn1InputStream.close();
            }

            // Add certificate subject key identifier extension
            certificateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier, false, ski);

            // Generate self signed certificate
            selfSignedCertificate = certificateGenerator.generate(kp.getPrivate(), "LunaJCAProvider");

            // Initialise key store
            ks = KeyStore.getInstance("Luna", "LunaJCAProvider");
            ks.load(null, null);

            // Create key entry alias based on hex encoded subject key identifier
            keyEntryAlias = new String(Hex.encode(ski.getKeyIdentifier()));

            // Store key entry along with its self signed certificate chain
            ks.setKeyEntry(keyEntryAlias, kp.getPrivate(), null, new Certificate[] { selfSignedCertificate });

            // Generate certificate request
            certificateRequest = new PKCS10CertificationRequest("SHA1withRSA", subject, kp.getPublic(), null, kp.getPrivate(), "LunaJCAProvider");

            // Encode certifiacte request
            encodedCertificateRequest = new String(Base64.encodeBase64(certificateRequest.getEncoded(), true));

            // Print out PEM encoded certificate request
            System.out.println("-----BEGIN CERTIFICATE REQUEST-----");
            System.out.print(encodedCertificateRequest);
            System.out.println("-----END CERTIFICATE REQUEST-----");

            System.out.println("Generated certificate request " + keyEntryAlias + " OK");
        }
        catch (RuntimeException re)
        {
			System.out.println(re.getMessage());
			return false;
            
        }
        catch (Exception e)
        {
			System.out.println(e.getMessage());
            return false;

        }
		return true;
    }

    private boolean processCommandLine (String[] args) 
    {
        Option keyLengthOption;
        Option subjectOption;
        Option daysOption;
        Options commandLineOptions;
        CommandLineParser clp;
        CommandLine cl;
        int keyLength;
        X500Principal subject;
        int days;

        keyLengthOption = null;
        subjectOption = null;
        daysOption = null;
        commandLineOptions = null;
        clp = null;
        cl = null;
        keyLength = 0;
        subject = null;
        days = 0;

        keyLengthOption = new Option("l", "keylength", true, "key bit length");
        keyLengthOption.setArgs(1);
        keyLengthOption.setOptionalArg(false);
        keyLengthOption.setArgName("bitlength");

        subjectOption = new Option("s", "subject", true, "subject distinguished name");
        subjectOption.setArgs(1);
        subjectOption.setOptionalArg(false);
        subjectOption.setArgName("subject");

        daysOption = new Option("d", "days", true, "expire certificate after number of days");
        daysOption.setArgs(1);
        daysOption.setOptionalArg(false);
        daysOption.setArgName("days");

        commandLineOptions = new Options();
        commandLineOptions.addOption(keyLengthOption);
        commandLineOptions.addOption(subjectOption);
        commandLineOptions.addOption(daysOption);

        clp = new PosixParser();
		if(args.length < 6)
		{
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp(APPLICATION_NAME, commandLineOptions, true);
			return false;
		}
        try
        {
            cl = clp.parse(commandLineOptions, args);

            try
            {
				if(null == cl.getOptionValue('l'))
				{
					HelpFormatter formatter = new HelpFormatter();
					formatter.printHelp(APPLICATION_NAME, commandLineOptions, true);
					return false;
				}
                keyLength = Integer.parseInt(cl.getOptionValue('l'));
				if( (keyLength < MIN_KEYLEN) || (keyLength > MAX_KEYLEN) )
				{
					System.out.println("KeyLength between 512 and 4096 is allowed");
					return false;
				}

            }
            catch (NumberFormatException nfe)
            {
				
               System.out.println("key length not valid integer " + nfe.getMessage());
			   return false;
            }

            try
            {
				if(null == cl.getOptionValue('s').replace(':', ' '))
				{
					HelpFormatter formatter = new HelpFormatter();
					formatter.printHelp(APPLICATION_NAME, commandLineOptions, true);
					return false;
				}
                subject = new X500Principal(cl.getOptionValue('s').replace(':', ' ')); // Hack to circumvent
                                                                                        // unsupported double
                                                                                        // quote in SP
            }
            catch (IllegalArgumentException iae)
            {
                 System.out.println("illegal subject distinguished name format");
				 return false;
            }

            try
            {
				if(null == cl.getOptionValue('d'))
				{
					HelpFormatter formatter = new HelpFormatter();
					formatter.printHelp(APPLICATION_NAME, commandLineOptions, true);
					return false;
				}
                days = Integer.parseInt(cl.getOptionValue('d'));
            }
            catch (NumberFormatException nfe)
            {
                 System.out.println("Days not valid integer " + nfe.getMessage());
				 return false;
            }

            // Ensure days is positive
            if (days < 1)
            {
                 System.out.println("Days must be in Valid Range(min 1,max 32767)");
				 return false;
            }
			
			if(days > 32767)
			{
				System.out.println("Days must be in Valid Range(min 1,max 32767)");
				return false;
			}

            if(false == generateCertificateRequest(keyLength, subject, days))
			{
				 System.out.println("Could not generate certificate request");
				 return false;
            }

			
        }
        catch (ParseException pe)
        {
            HelpFormatter formatter = new HelpFormatter();

            formatter.printHelp(APPLICATION_NAME, commandLineOptions, true);

            System.err.println("Parsing of arguments failed");
			return false;

            
        }
		return true;
    }

    private Date addDays (Date notBefore, int days)
    {
        Date notAfter;
        GregorianCalendar gc;

        notAfter = null;
        gc = null;

        // Instantiate GregorianCalendar in GMT time zone
        gc = new GregorianCalendar(TimeZone.getTimeZone("GMT"));

        // Set not before date
        gc.setTime(notBefore);

        // Add number of days specified
        gc.add(Calendar.DAY_OF_YEAR, days);

        notAfter = gc.getTime();

        return notAfter;
    }

    private BigInteger generateSerialNumber () throws NoSuchAlgorithmException
    {
        byte[] serialNumber;
        SecureRandom rng;

        serialNumber = null;
        rng = null;

        // Instantiate random number generator
        rng = SecureRandom.getInstance("LunaRNG");

        serialNumber = new byte[32];

        rng.nextBytes(serialNumber);

        return new BigInteger(1, serialNumber);
    }

    /**
     * Simple main method - passes arguments to GenerateCertificateRequest
     * 
     * @param args Standard command line arguments
     */
    public static void main (String[] args)
    {
	   	boolean isLoggedIn = Common.isPartitionLoggedIn();
		if(Common.partitionAndMofnAuthentication(isLoggedIn)!=0)
		{
		  System.out.println("Authentication Failed");
		  return;
		}
        new GenerateCertificateRequest(args);
		if(isLoggedIn==false)
		{
			Common.partition_logout();
		}
    }
}
