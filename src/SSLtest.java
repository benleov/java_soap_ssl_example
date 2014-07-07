import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;

public class SSLtest {

	/**
	 * Path to the clients keystore
	 */
	private static final String CLIENT_KEYSTORE_PATH = "docs/certs/example_client.jks";

	/**
	 * Password for the clients keystore
	 */
	private static final String CLIENT_KEYSTORE_PASSWORD = "password";

	/**
	 * The servers certificate's alias within the clients keystore.
	 */
	private static final String SERVER_CERTIFICATE_ALIAS = "www.examplesite.com";

	/**
	 * URL to our SOAP UI service
	 */
	private static final String SOAP_URI = "https://127.0.0.1:8443/";

	private static final String URN = "urn:examples:helloservice";

	/**
	 * Loads the KeyStore using the default KeyStore type (JKS) with the given
	 * file path and password.
	 * 
	 * @param filePath
	 *            Path to the KeyStore.
	 * @param password
	 *            The KeyStores password.
	 * @return Returns the KeyStore.
	 * @throws NoSuchAlgorithmException
	 * @see Keystore#load(InputStream, char[])
	 * @throws CertificateException
	 * @see Keystore#load(InputStream, char[])
	 * @throws IOException
	 * @see FileInputStream()
	 * @throws KeyStoreException
	 * @see Keystore#getInstance()
	 */
	private KeyStore loadKeystore(String filePath, char[] password)
			throws NoSuchAlgorithmException, CertificateException, IOException,
			KeyStoreException {

		FileInputStream is = new FileInputStream(new File(filePath));

		final KeyStore keystore = KeyStore.getInstance(KeyStore
				.getDefaultType());

		keystore.load(is, password);

		return keystore;
	}

	public void run() throws NoSuchAlgorithmException, CertificateException,
			KeyStoreException, IOException, KeyManagementException,
			UnrecoverableKeyException, SOAPException {

		/*
		 * Load the keystore
		 */
		char[] password = CLIENT_KEYSTORE_PASSWORD.toCharArray();
		KeyStore keystore = loadKeystore(CLIENT_KEYSTORE_PATH, password);

		/*
		 * Get the servers trusted certificate.
		 */
		final Certificate trusted = keystore
				.getCertificate(SERVER_CERTIFICATE_ALIAS);

		/*
		 * Create a trust manager that validates the servers certificate
		 */
		TrustManager[] trustManager = new TrustManager[] { new X509TrustManager() {
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkClientTrusted(X509Certificate[] certs,
					String authType) {
			}

			public void checkServerTrusted(X509Certificate[] certs,
					String authType) throws CertificateException {

				if (certs == null || certs.length == 0) {
					throw new IllegalArgumentException(
							"null or zero-length certificate chain");
				}

				if (authType == null || authType.length() == 0) {
					throw new IllegalArgumentException(
							"null or zero-length authentication type");
				}

				// check if certificate sent is your CA's

				if (!certs[0].equals(trusted)) {

					// check if its been signed by the CA

					try {
						certs[0].verify(trusted.getPublicKey());
					} catch (InvalidKeyException | NoSuchAlgorithmException
							| NoSuchProviderException | SignatureException e) {
						throw new CertificateException(e);
					}
				}

				certs[0].checkValidity();
			}
		} };

		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
				.getDefaultAlgorithm());

		kmf.init(keystore, password);

		// set the trust manager
		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(kmf.getKeyManagers(), trustManager,
				new java.security.SecureRandom());

		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

		// create an all-trusting host name verifier
		HostnameVerifier allHostsValid = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		};

		HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

		// setup an example soap message

		MessageFactory messageFactory = MessageFactory.newInstance();
		SOAPMessage soapMessage = messageFactory.createMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		SOAPEnvelope envelope = soapPart.getEnvelope();

		envelope.addNamespaceDeclaration("example", SOAP_URI);
		envelope.addNamespaceDeclaration("urn", URN);
		/**
		 * <pre>
		 * 		<soapenv:Envelope 
		 * 				xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
		 * 				xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
		 * 				xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
		 * 				xmlns:urn="urn:examples:helloservice">
		 * 		   <soapenv:Header/>
		 * 		   <soapenv:Body>
		 * 		      <urn:sayHello soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
		 * 		         <firstName xsi:type="xsd:string">Example First Name</firstName>
		 * 		      </urn:sayHello>
		 * 		   </soapenv:Body>
		 * 		</soapenv:Envelope>
		 * </pre>
		 */

		SOAPBody soapBody = envelope.getBody();
		SOAPElement soapBodyElem = soapBody.addChildElement("sayHello", "urn");
		SOAPElement soapBodyElem1 = soapBodyElem.addChildElement("firstName");
		soapBodyElem1.addTextNode("Example First Name");

		MimeHeaders headers = soapMessage.getMimeHeaders();
		headers.addHeader("SOAPAction", SOAP_URI + "VerifyEmail");
		soapMessage.saveChanges();

		
		// send to the server
		URL url = new URL(SOAP_URI);
		URLConnection con = url.openConnection();
		con.setDoOutput(true);
		soapMessage.writeTo(con.getOutputStream());

		// read in response and print it to screen
		Reader reader = new InputStreamReader(con.getInputStream());

		while (true) {

			int ch = reader.read();
			if (ch == -1) {
				break;
			}

			System.out.print((char) ch);
		}
	}

	public static void main(String[] args) throws KeyManagementException,
			UnrecoverableKeyException, NoSuchAlgorithmException,
			CertificateException, KeyStoreException, IOException, SOAPException {

		SSLtest test = new SSLtest();
		test.run();
	}
}