package Utils.conexion;

import Utils.conexion.Operaciones;
import Utils.socket.SignedReader;
import Utils.socket.SignedWriter;
import graphic.DataSelector;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.net.Inet4Address;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import javax.swing.JOptionPane;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author expploitt
 */
public class SSL_client {

    private static final int PORT = 8080;
    private static final String RAIZ = "";
    private static String keyStore, trustStore;
    public static String keyStorePass, trustStorePass;

    public static final int NO_OPERATION = 0;
    public static final int REGISTRAR = 1;
    public static final int RECUPERAR = 2;
    public static final int LISTAR = 3;
    public static final int READY = 255;

    public static final String FAIL_CERT = "CERTIFICADO INCORRECTO";
    public static final String FAIL_SIGN = "FIRMA INCORRECTA";
    public static final String OK = "OK";

    public SSL_client(String keyStore, String trustStore) {
        SSL_client.keyStore = keyStore;
        SSL_client.trustStore = trustStore;
        
        DataSelector vent = new DataSelector(this,keyStore, trustStore);
        vent.setLocationByPlatform(true);
        vent.setVisible(true);
    }

    public static byte[] getSHA512(String docPath) throws FileNotFoundException, NoSuchAlgorithmException, IOException {
        FileInputStream fmensaje = new FileInputStream(docPath);
        MessageDigest md = null;
        int longbloque;
        byte bloque[] = new byte[1024];
        long filesize = 0;
        //SHA-512
        md = MessageDigest.getInstance("SHA-512");
        while ((longbloque = fmensaje.read(bloque)) > 0) {
            filesize = filesize + longbloque;
            md.update(bloque, 0, longbloque);
        }
        fmensaje.close();
        return md.digest();
    }

    public void definirKeyStores() {

        //--------   Para Debugguear el handshake ---------
        //System.setProperty("javax.net.debug", "all");
        // ----  Almacenes mios  -----------------------------
        // Almacen de claves
        System.setProperty("javax.net.ssl.keyStore", keyStore);
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePass);

        // Almacen de confianza
        System.setProperty("javax.net.ssl.trustStore",  trustStore);
        System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePass);

    }

    public static byte[] sign(String docPath, String keyStore, String entry_alias) throws KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, UnrecoverableEntryException, InvalidKeyException, SignatureException, CertificateException {

        FileInputStream fmensaje = new FileInputStream(docPath);

        String provider = "SunJCE";
        String algoritmo = "SHA256withRSA";
        byte bloque[] = new byte[1024];
        long filesize = 0;
        int longbloque;

        // Variables para el KeyStore
        KeyStore ks;
        char[] ks_password = keyStorePass.toCharArray();
        char[] key_password = keyStorePass.toCharArray();

        System.out.println("******************************************* ");
        System.out.println("*               FIRMA                     * ");
        System.out.println("******************************************* ");

        // Obtener la clave privada del keystore
        ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(keyStore), ks_password);

        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(entry_alias, new KeyStore.PasswordProtection(key_password));
        System.err.println(pkEntry);
        PrivateKey privateKey = pkEntry.getPrivateKey();

        // Visualizar clave privada
        System.out.println("*** CLAVE PRIVADA ***");
        System.out.println("Algoritmo de Firma (sin el Hash): " + privateKey.getAlgorithm());
        System.out.println(privateKey);

        // Creamos un objeto para firmar/verificar
        Signature signer = Signature.getInstance(algoritmo);

        // Inicializamos el objeto para firmar
        signer.initSign(privateKey);

        // Para firmar primero pasamos el hash al mensaje (metodo "update")
        // y despues firmamos el hash (metodo sign).
        byte[] firma = null;

        while ((longbloque = fmensaje.read(bloque)) > 0) {
            filesize = filesize + longbloque;
            signer.update(bloque, 0, longbloque);
        }

        firma = signer.sign();

        System.out.println("*** FIRMA: ****");
        for (int i = 0; i < firma.length; i++) {
            System.out.print(firma[i] + " ");
        }
        System.out.println();
        System.out.println();

        fmensaje.close();

        return firma;

    }

    public static boolean verify(String docPath, byte[] firma) throws FileNotFoundException, CertificateException,
            InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException, KeyStoreException {

        /**
         * *****************************************************************
         * Verificacion
         * ****************************************************************
         */
        System.out.println("************************************* ");
        System.out.println("        VERIFICACION                  ");
        System.out.println("************************************* ");

        byte bloque[] = new byte[1024];
        long filesize = 0;
        int longbloque;

        KeyStore ks;
        char[] ks_password = trustStorePass.toCharArray();

        ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(trustStore), ks_password);

        Enumeration<String> aliases = ks.aliases();
        System.out.println((String) aliases.nextElement());
        while (aliases.hasMoreElements()) {

            FileInputStream fmensajeV = new FileInputStream(docPath);

            String alias = aliases.nextElement();

            // Obtener la clave publica del keystore
            PublicKey publicKey = ks.getCertificate(alias).getPublicKey();

            System.out.println("*** CLAVE PUBLICA ***");
            System.out.println(publicKey);

            // Obtener el usuario del Certificado tomado del KeyStore.
            // Hay que traducir el formato de certificado del formato del
            // keyStore
            // al formato X.509. Para eso se usa un CertificateFactory.
            byte[] certificadoRaw = ks.getCertificate(alias).getEncoded();
            ByteArrayInputStream inStream;
            inStream = new ByteArrayInputStream(certificadoRaw);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            // Creamos un objeto para verificar, pasandole el algoritmo leido
            // del certificado.
            Signature verifier = Signature.getInstance(cert.getSigAlgName());
            System.out.println(cert.getSigAlgName());
            // Inicializamos el objeto para verificar
            verifier.initVerify(publicKey);

            while ((longbloque = fmensajeV.read(bloque)) > 0) {
                filesize = filesize + longbloque;
                verifier.update(bloque, 0, longbloque);
            }

            boolean resultado;
            System.out.println((String) aliases.nextElement());
            try {
                resultado = verifier.verify(firma);
            } catch (Exception e) {
                resultado = false;
            }
            System.out.println();
            if (resultado == true) {
                System.out.print("Verificacion correcta de la Firma");
                fmensajeV.close();
                return true;

            }

            fmensajeV.close();

        }
        System.out.print("Fallo de verificacion de firma");
        return false;
    }

    public static boolean verify_sigRD(byte[] certificadoRaw, String docPath, byte[] firma, String selloTemporal, Long idRegistro, byte[] firma_propia) throws FileNotFoundException, CertificateException,
            InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException, KeyStoreException {

        /**
         * *****************************************************************
         * Verificacion
         * ****************************************************************
         */
        System.out.println("************************************* ");
        System.out.println("        VERIFICACION                  ");
        System.out.println("************************************* ");
        byte bloque[] = new byte[1024];
        long filesize = 0;
        int longbloque;
        FileInputStream fmensajeV = new FileInputStream(docPath);

        ByteArrayInputStream inStream;
        inStream = new ByteArrayInputStream(certificadoRaw);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
        PublicKey publicKey = cert.getPublicKey();
        // Creamos un objeto para verificar, pasandole el algoritmo leido
        // del certificado.
        Signature verifier = Signature.getInstance("SHA256withRSA");
        //System.out.println(cert.getSigAlgName());  saca MD5withRSA, pero usamos el otro
        // Inicializamos el objeto para verificar
        verifier.initVerify(publicKey);

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(idRegistro);
        verifier.update(buffer.array());
        verifier.update(selloTemporal.getBytes());
        while ((longbloque = fmensajeV.read(bloque)) > 0) {
            filesize = filesize + longbloque;
            verifier.update(bloque, 0, longbloque);
        }
        verifier.update(firma_propia);

        boolean resultado = true;
        try {
            resultado = verifier.verify(firma);
        } catch (Exception e) {
            resultado = false;
        }
        if (resultado == true) {
            System.out.print("Verificacion correcta de la Firma");

        }

        fmensajeV.close();
        return resultado;
    }

    public static boolean verifyCert(byte[] certificado) {
        try {
            KeyStore ks;
            ByteArrayInputStream inStream;
            PublicKey publicKey;
            char[] ks_password;

            ks_password = trustStorePass.toCharArray();
            ks = KeyStore.getInstance("JCEKS");
            ks.load(new FileInputStream(RAIZ + trustStore), ks_password);

            // Obtener el certificado de un array de bytes
            // Obtener la clave publica del keystore
            // Obtener el certificado de un array de bytes
            inStream = new ByteArrayInputStream(certificado);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            // Listamos los alias y después los recorremos en busca de un
            // certificado que valga
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {

                // Obtener la clave publica del keystore
                publicKey = ks.getCertificate(aliases.nextElement()).getPublicKey();

                try {

                    cert.verify(publicKey);
                    System.out.println("\nCertificado correcto");

                    return true;

                } catch (InvalidKeyException e) {

                } catch (SignatureException ex) {

                } catch (Exception ex) {
                    // capturar el resto de excepciones posibles para que no se
                    // cuelgue el bucle por no haber capturado la excepcion
                }
            }
        } catch (Exception ex) {

        }
        System.out.println("Certificado incorrecto");
        return false;
    }

    public static X509Certificate getCertificate(String keyStore, String keyStorePwd, String aliasCertificate) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {

        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(new FileInputStream(keyStore), keyStorePwd.toCharArray());
        X509Certificate cert;

        cert = (X509Certificate) keystore.getCertificate(aliasCertificate);
        return cert;
    }

}
