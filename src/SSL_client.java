
import Utils.socket.SignedReader;
import Utils.socket.SignedWriter;
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
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

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

    private static final String HOST = "localhost";
    private static final int PORT = 8080;
    private static final String RAIZ = "";
    private static String keyStore, trustStore;
    private static String keyStorePass, trustStorePass, clientCN, tipoClave, ipServidor;

    public static final int NO_OPERATION = 0;
    public static final int REGISTRAR = 1;
    public static final int RECUPERAR = 2;
    public static final int LISTAR = 3;
    public static final int READY = 255;

    public static final String FAIL_CERT = "CERTIFICADO INCORRECTO";
    public static final String FAIL_SIGN = "FIRMA INCORRECTA";
    public static final String OK = "OK";

    public static void main(String[] args) {

        try {
            /*
            Principal vent = new Principal();
            vent.setLocationByPlatform(true);
            vent.setVisible(true);
             */
            BufferedReader buffer = new BufferedReader(new InputStreamReader(System.in));

            if (args.length != 2) {
                System.out.println("Uso: SSL_client keyStoreFile trustStoreFile");
                System.exit(0);
            }

            keyStore = args[0].trim();
            trustStore = args[1].trim();

            System.out.print("Introduzca la contraseña del keyStore: ");
            System.out.print("> ");
            keyStorePass = buffer.readLine().trim();

            System.out.print("Introduzca la contraseña del trustStore: ");
            System.out.print("> ");
            trustStorePass = buffer.readLine().trim();

            System.out.print("Introduzca su identificador (email@example.com): ");
            System.out.print("> ");
            clientCN = buffer.readLine().trim();

            System.out.print("Introduzca el tipo de clave empleado (RSA/DSA): ");
            System.out.print("> ");
            tipoClave = buffer.readLine().toLowerCase();
            
             System.out.print("Introduzca la dirección del servidor: ");
            System.out.print("> ");
            ipServidor = buffer.readLine().trim();

            new SSL_client().definirKeyStores();

            SSLSocketFactory socketFactory = (SSLSocketFactory) SSL_client.getServerSocketFactory("TLS");
            SSLSocket socket = (SSLSocket) socketFactory.createSocket(ipServidor, PORT);

            String[] suites = socket.getSupportedCipherSuites();
            System.out.println("\n***** SELECCIONE UNA CYPHER SUITE ***** \n");

            for (int i = 1; i < suites.length + 1; i++) {
                System.out.println(i + ".-" + suites[i - 1]);
            }

            int suite;

            do {
                System.out.println("Indique el número de la suite elegida: ");
                System.err.println("> ");
                suite = Integer.parseInt(buffer.readLine());
            } while (suite < 1 || suite > suites.length);

            String aux = suites[suite];
            String[] newSuites = {aux};
            suites = null;
            socket.setEnabledCipherSuites(newSuites);

            System.out.println("Comienzo SSL Handshake -- Cliente y Server Autenticados");

            socket.startHandshake();

            System.out.println("Fin OK SSL Handshake");

            new SSL_client().mainMenu(buffer);

            System.out.println("¿Qué desea hacer?");
            System.out.print("> ");

            switch (buffer.readLine()) {
                case "1":

                    System.out.println("********************************************");
                    System.out.println("*          REGISTRAR DOCUMENTO             *");
                    System.out.println("********************************************");

                    boolean error = false;
                    String id_propietario = null;
                    String nombreDoc = null;
                    String tipoConfidencialidad = null;
                    String documento = null;

                    do {
                        System.out.println("\nUso: \n"
                                + "id_propietario:           example@alumnos.uvigo.es \n"
                                + "nombreDoc:                nombre de fichero (100 caract. max.)\n "
                                + "tipoConfidencialidad:     PRIVADO/PUBLICO \n"
                                + "documento:                documento a registrar \n");

                        System.out.println("> ");
                        String entrada = buffer.readLine();
                        String[] partes = entrada.split("\\s+");

                        if (partes.length == 4) {

                            error = false;
                            id_propietario = partes[0].trim();
                            nombreDoc = partes[1].trim();
                            tipoConfidencialidad = partes[2].trim();
                            documento = partes[3].trim();

                            /*if (nombreDoc.length() > 100) {
                                error = true;
                            } else if (!tipoConfidencialidad.equalsIgnoreCase("privado") || !tipoConfidencialidad.equalsIgnoreCase("publico")) {
                                error = true;
                            }*/
                        } else {
                            error = true;
                        }

                    } while (error);

                    byte[] firma = null;
                    X509Certificate cert = null;
                    boolean confidencialidad = false;

                    confidencialidad = tipoConfidencialidad.equalsIgnoreCase("privado");

                    try {

                        firma = SSL_client.sign(documento, keyStore, clientCN + "-firma-" + tipoClave);
                        cert = SSL_client.getCertificate(keyStore, keyStorePass, clientCN + "-firma-" + tipoClave);

                        /*-------- ESCRIBIMOS EL CÓDIGO DE OPERACIÓN ---------*/
                        SignedWriter signedWriter = new SignedWriter(socket);
                        SignedReader socketReader = new SignedReader(socket);
                        signedWriter.write(REGISTRAR);
                        signedWriter.flush();

                        if (socketReader.read() == NO_OPERATION) {
                            System.out.println("Operación no operativa en el servidor");
                            System.exit(0);
                        }

                        System.out.println(cert.getIssuerDN().getName());
                        signedWriter.SendSignedFile(id_propietario, nombreDoc, confidencialidad, documento, firma, cert);

                        String resultadoOP = socketReader.readString();

                        if (resultadoOP.equalsIgnoreCase(SSL_client.OK)) {

                            System.out.println("\n****** REGISTRO CORRECTO *******");
                            System.out.println("Atención! A continuación se muestra el identificador de documento. Guardelo si desea recuperar en un futuro el docuento registrado!");
                            System.out.println("El ID de su registro es: ");
                            System.out.println("\n********************************************");
                            System.out.println("*         " + socketReader.readLong() + "                                *");
                            System.out.println("********************************************");

                        } else {
                            System.out.println(resultadoOP);
                        }

                    } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException | InvalidKeyException | SignatureException | CertificateException ex) {
                        Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    /*AQUI DEBERIAMOS HACER LA ESCRITURA */
                    break;

                case "2":
                    System.out.println("********************************************");
                    System.out.println("*          RECUPERAR DOCUMENTO             *");
                    System.out.println("********************************************");

                    error = false;
                    String id_registro = "";

                    do {
                        System.out.println("\nUso: \n"
                                + "id_registro:           numero registro del documento que queremos recuperar \n");

                        System.out.println("> ");
                        String entrada = buffer.readLine();
                        String[] partes = entrada.split("\\s+");

                        if (partes.length == 1) {

                            error = false;
                            id_registro = partes[0].trim();

                        } else {
                            error = true;
                        }

                    } while (error);

                    try {
                        /*-------- ESCRIBIMOS EL CÓDIGO DE OPERACIÓN ---------*/
                        SignedWriter signedWriter = new SignedWriter(socket);
                        SignedReader socketReader = new SignedReader(socket);
                        signedWriter.write(RECUPERAR);
                        signedWriter.flush();

                        if (socketReader.read() == NO_OPERATION) {
                            System.out.println("Operación no operativa en el servidor");
                            System.exit(0);
                        }

                        cert = SSL_client.getCertificate(keyStore, keyStorePass, clientCN + "-auth-" + tipoClave);

                        boolean sendOk = signedWriter.sendRecoveryRequest(id_registro, cert);

                        if (!sendOk) {

                            System.out.println("Error enviando el identificador y el certificado");
                            System.exit(0);

                        }

                        String resultadoOP = socketReader.readString();

                        if (resultadoOP.equalsIgnoreCase(SSL_client.FAIL_CERT)) {
                            System.out.println(SSL_client.FAIL_CERT);
                        } else if (resultadoOP.equalsIgnoreCase(SSL_client.FAIL_SIGN)) {
                            System.out.println(SSL_client.FAIL_SIGN);
                        } else {
                            System.out.println("\n****** REQUEST CORRECTO *******");
                        }

                    } catch (FileNotFoundException ex) {
                        Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (KeyStoreException ex) {
                        Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (UnrecoverableKeyException ex) {
                        Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (CertificateException ex) {
                        Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    break;

                case "3":

                    System.out.println("********************************************");
                    System.out.println("*          LISTAR DOCUMENTOS               *");
                    System.out.println("********************************************");

                    try {

                        /*-------- ESCRIBIMOS EL CÓDIGO DE OPERACIÓN ---------*/
                        SignedWriter signedWriter = new SignedWriter(socket);
                        SignedReader signedReader = new SignedReader(socket);
                        signedWriter.write(LISTAR);
                        signedWriter.flush();

                        if (signedReader.read() == NO_OPERATION) {
                            System.out.println("Operación no operativa en el servidor");
                            System.exit(0);
                        }

                        System.out.println(clientCN + "-auth-" + tipoClave);
                        cert = SSL_client.getCertificate(keyStore, keyStorePass, clientCN + "-auth-" + tipoClave);

                        boolean sendOk = signedWriter.sendDocumentListRequest(cert);

                        if (!sendOk) {

                            System.out.println("Error el certificado de autenticación del cliente");
                            System.exit(0);

                        }

                        String resultadoOP = signedReader.readString();

                        if (resultadoOP.equalsIgnoreCase(SSL_client.FAIL_CERT)) {
                            System.out.println(SSL_client.FAIL_CERT);
                        } else {
                            System.out.println("\n****** LISTADO CORRECTO *******");
                        }

                        ArrayList<Object[]> confidenciales = signedReader.ReadListDocumentsRequest();
                        ArrayList<Object[]> noConfidenciales = signedReader.ReadListDocumentsRequest();

                        if (confidenciales != null) {
                            System.out.println("\n\n\n\n***** DOCUMENTOS PRIVADOS *****\n"
                                        + "***************************************");
                            for (int i = 0; i < confidenciales.size(); i++) {                     
                                System.out.println("DOCUMENTO Nº" + (i + 1));
                                System.out.println("idRegistro:      " + (long) confidenciales.get(i)[0]);
                                System.out.println("idPropietario:   " + (String) confidenciales.get(i)[1]);
                                System.out.println("nombreDoc:       " + (String) confidenciales.get(i)[2]);
                                System.out.println("selloTemporal:   " + (String) confidenciales.get(i)[3]);
                                System.out.println("***************************************");
                            }
                        } else {
                            System.out.println("No tiene ningún documento registrado de forma confidencial");
                        }

                        if (noConfidenciales != null) {
                            System.out.println("\n\n\n\n***** DOCUMENTOS PÚBLICOS *****\n"
                                    + "***************************************");
                            for (int i = 0; i < noConfidenciales.size(); i++) {
                                System.out.println("DOCUMENTO Nº" + (i + 1));
                                System.out.println("idRegistro:      " + (long) noConfidenciales.get(i)[0]);
                                System.out.println("idPropietario:   " + (String) noConfidenciales.get(i)[1]);
                                System.out.println("nombreDoc:       " + (String) noConfidenciales.get(i)[2]);
                                System.out.println("selloTemporal:   " + (String) noConfidenciales.get(i)[3]);
                                System.out.println("***************************************");
                            }
                        } else {
                            System.out.println("No tiene ningún documento registrado de forma pública");
                        }

                    } catch (FileNotFoundException ex) {
                        Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (KeyStoreException ex) {
                        Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (UnrecoverableKeyException ex) {
                        Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (CertificateException ex) {
                        Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    break;

                default:
                    System.out.println("Saliendo de la aplicación...");
                    System.exit(0);
            }

        } catch (IOException ex) {
            Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
        }

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
        return md.digest();
    }

    public void mainMenu(BufferedReader bf) throws IOException {

        System.out.println("********************************************");
        System.out.println("* Bienvenido a Watermelon SSL/TLS Register *");
        System.out.println("********************************************");

        System.out.println("1) Registrar documento");
        System.out.println("2) Recuperar documento");
        System.out.println("3) Listar documentos");
        System.out.println("4) Salir");
    }

    public void definirKeyStores() {

        //--------   Para Debugguear el handshake ---------
        //System.setProperty("javax.net.debug", "all");
        // ----  Almacenes mios  -----------------------------
        // Almacen de claves
        System.setProperty("javax.net.ssl.keyStore", RAIZ + keyStore + ".jce");
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePass);

        // Almacen de confianza
        System.setProperty("javax.net.ssl.trustStore", RAIZ + trustStore + ".jce");
        System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePass);

    }

    /**
     * ****************************************************
     * getServerSocketFactory(String type) {}
     * ***************************************************
     */
    private static SocketFactory getServerSocketFactory(String type) {

        if (type.equals("TLS")) {

            SSLSocketFactory ssf;

            try {

                // Establecer el keymanager para la autenticacion del servidor
                SSLContext ctx;
                KeyManagerFactory kmf;
                TrustManagerFactory tmf;
                KeyStore ks, ts;

                char[] contraseñaKeyStore = keyStorePass.toCharArray();
                char[] contraseñaTrustStore = trustStorePass.toCharArray();

                ctx = SSLContext.getInstance("TLS");
                kmf = KeyManagerFactory.getInstance("SunX509");
                tmf = TrustManagerFactory.getInstance("SunX509");

                ks = KeyStore.getInstance("JCEKS");
                ts = KeyStore.getInstance("JCEKS");

                ks.load(new FileInputStream(RAIZ + keyStore + ".jce"), contraseñaKeyStore);
                ts.load(new FileInputStream(RAIZ + trustStore + ".jce"), contraseñaTrustStore);

                kmf.init(ks, contraseñaKeyStore);
                tmf.init(ts);

                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

                ssf = ctx.getSocketFactory();

                return ssf;

            } catch (Exception e) {

                e.printStackTrace();
            }

        } else {
            System.out.println("Usando la Factoria socket por defecto (no SSL)");

            return SocketFactory.getDefault();
        }

        return null;
    }

    private static byte[] sign(String docPath, String keyStore, String entry_alias) throws KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, UnrecoverableEntryException, InvalidKeyException, SignatureException, CertificateException {

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

        ks.load(new FileInputStream(keyStore + ".jce"), ks_password);

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

        double v = firma.length;

        System.out.println("*** FIRMA: ****");
        for (int i = 0; i < firma.length; i++) {
            System.out.print(firma[i] + " ");
        }
        System.out.println();
        System.out.println();

        fmensaje.close();

        return firma;

    }

    private static boolean verify(String docPath, byte[] firma, String entry_alias) throws FileNotFoundException, CertificateException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException, KeyStoreException {

        /**
         * *****************************************************************
         * Verificacion
         * ****************************************************************
         */
        System.out.println("************************************* ");
        System.out.println("        VERIFICACION                  ");
        System.out.println("************************************* ");

        FileInputStream fmensajeV = new FileInputStream(docPath);
        byte bloque[] = new byte[1024];
        long filesize = 0;
        int longbloque;

        KeyStore ks;
        char[] ks_password = keyStorePass.toCharArray();
        char[] key_password = keyStorePass.toCharArray();

        ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(keyStore + ".jce"), ks_password);

        // Obtener la clave publica del keystore
        PublicKey publicKey = ks.getCertificate(entry_alias).getPublicKey();

        System.out.println("*** CLAVE PUBLICA ***");
        System.out.println(publicKey);

        // Obtener el usuario del Certificado tomado del KeyStore.
        //   Hay que traducir el formato de certificado del formato del keyStore
        //	 al formato X.509. Para eso se usa un CertificateFactory.
        byte[] certificadoRaw = ks.getCertificate(entry_alias).getEncoded();
        ByteArrayInputStream inStream = null;
        inStream = new ByteArrayInputStream(certificadoRaw);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

        // Creamos un objeto para verificar, pasandole el algoritmo leido del certificado.
        Signature verifier = Signature.getInstance(cert.getSigAlgName());

        // Inicializamos el objeto para verificar
        verifier.initVerify(publicKey);

        while ((longbloque = fmensajeV.read(bloque)) > 0) {
            filesize = filesize + longbloque;
            verifier.update(bloque, 0, longbloque);
        }

        boolean resultado = false;

        resultado = verifier.verify(firma);

        System.out.println();
        if (resultado == true) {
            System.out.println("Verificacion correcta de la Firma");

        } else {
            System.out.println("Fallo de verificacion de firma");
            return false;
        }

        fmensajeV.close();
        return true;
    }

    private static X509Certificate getCertificate(String keyStore, String keyStorePwd, String aliasCertificate) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {

        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(new FileInputStream(keyStore + ".jce"), keyStorePwd.toCharArray());
        X509Certificate cert;

        cert = (X509Certificate) keystore.getCertificate(aliasCertificate);

//        byte[] certificadoRaw = keystore.getCertificate(aliasCertificate).getEncoded();
//        ByteArrayInputStream inStream = null;
//        inStream = new ByteArrayInputStream(certificadoRaw);
//
//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        cert = (X509Certificate) cf.generateCertificate(inStream);
        return cert;
    }
}
