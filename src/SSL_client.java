
import Utils.data.CSVHandler;
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
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import javax.xml.bind.DatatypeConverter;

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

                    byte[] sigRD = null;
                    X509Certificate cert = null;
                    boolean confidencialidad = false;

                    confidencialidad = tipoConfidencialidad.equalsIgnoreCase("privado");

                    try {

                        sigRD = SSL_client.sign(documento, keyStore, clientCN + "-firma-" + tipoClave);
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
                        signedWriter.SendSignedFile(id_propietario, nombreDoc, confidencialidad, documento, sigRD, cert);

                        String resultadoOP = socketReader.readString();

                        if (resultadoOP.equalsIgnoreCase(SSL_client.OK)) {
                            Object[] obs = socketReader.readRegisterResponse();
                            Long idRegistro = (Long) obs[0];
                            String sello = (String) obs[1];
                            byte[] sigRD_recuperada = (byte[]) obs[2];
                            byte[] certRAW = (byte[]) obs[3];
                            if (!verifyCert(certRAW)) {
                                System.out.println("CERTIFICADO DE REGISTRADOR INCORRECTO");
                                return;
                            }
                            if (!verify_sigRD(certRAW, documento, sigRD_recuperada, sello, idRegistro, sigRD)) {
                                System.out.println("FIRMA INCORRECTA DEL REGISTRADOR");
                                return;
                            }
                            if (!new CSVHandler().newEntry(idRegistro, getSHA512(documento))) {
                                System.out.println("NO SE HA PODIDO ALMACENAR EL SHA512");
                                return;
                            }
                            new File(documento).delete();
                            System.out.println("\n****** REGISTRO CORRECTO *******");
                            System.out.println("Atención! A continuación se muestra el identificador de documento. Guardelo si desea recuperar en un futuro el docuento registrado!");
                            System.out.println("El ID de su registro es: ");
                            System.out.println("\n********************************************");
                            System.out.println("*         " + idRegistro + "                                *");
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

                        String documentStatus = socketReader.readString();

                        if (documentStatus.equals("DOCUMENTO INEXISTENTE")) {
                            System.out.println(documentStatus);
                            System.exit(0);
                        }

                        String confidencial = socketReader.readString();

                        System.out.println(confidencial);

                        if (confidencial.equals("PUBLICO")) {

                            String ruta_temp = getRutaTemporal();

                            Object[] datos = socketReader.ReadRecoveryResponse(new File(ruta_temp));

                            String destino = "Recibido/";
                            String nombre_fichero = (String) datos[5];
                            boolean error_recibiendo = false;
                            if (!DatatypeConverter.printHexBinary(new CSVHandler().getSHA512(Long.parseLong(id_registro))).equals(DatatypeConverter.printHexBinary(SSL_client.getSHA512(ruta_temp)))) {
                                System.out.println("DOCUMENTO ALTERADO POR EL REGISTRADOR");
                                error_recibiendo = true;
                            }
                            destino += nombre_fichero;
                            if (error_recibiendo) {
                                System.out.println("No se ha guardado el fichero.");
                                new File(ruta_temp).delete();
                            }
                            Files.move(new File(ruta_temp).toPath(), new File(destino).toPath(), StandardCopyOption.REPLACE_EXISTING);
                            System.out.println("Se ha guardado el fichero en " + destino);
                        } else {

                            String resultadoOP = socketReader.readString();
                            if (resultadoOP.equalsIgnoreCase(SSL_client.FAIL_CERT)) {
                                System.out.println(SSL_client.FAIL_CERT);
                            } else if (resultadoOP.equalsIgnoreCase(SSL_client.FAIL_SIGN)) {
                                System.out.println(SSL_client.FAIL_SIGN);
                            } else {
                                System.out.println("\n****** CERTIFICADO CORRECTO *******");
                            }

                            String acceso = socketReader.readString();
                            System.out.println(acceso);
                            if (acceso.equals("ACCESO NO PERMITIDO")) {
                                System.exit(0);
                            }

                            String ruta_temp = getRutaTemporal();

                            Object[] datos = socketReader.ReadRecoveryResponse(new File(ruta_temp));
                            String sello = (String) datos[2];
                            Long id_registro_leido = Long.parseLong((String) datos[1]);
                            String destino = "Recibido/";
                            String nombre_fichero = (String) datos[5];
                            destino += nombre_fichero;

                            byte[] firma_registrador = (byte[]) datos[3];
                            byte[] cert_server = (byte[]) datos[4];
                            boolean error_recibiendo = false;
                            if (!SSL_client.verifyCert(cert_server)) {
                                System.out.println("CERTIFICADO SERVIDOR NO VALIDO");
                                error_recibiendo = true;
                            } else {
                                System.out.println("CERTIFICADO SERVIDOR CORRECTO");
                            }
                            byte[] firma_propia = sign(ruta_temp, keyStore, clientCN + "-firma-" + tipoClave);
                            if (!SSL_client.verify_sigRD(cert_server, ruta_temp, firma_registrador, sello, id_registro_leido, firma_propia)) {
                                System.out.println("FALLO DE FIRMA DEL REGISTRADOR");
                                error_recibiendo = true;
                            } else {
                                System.out.println("FIRMA DEL REGISTRADOR CORRECTA");
                            }

                            if (!DatatypeConverter.printHexBinary(new CSVHandler().getSHA512(Long.parseLong(id_registro))).equals(DatatypeConverter.printHexBinary(SSL_client.getSHA512(ruta_temp)))) {
                                System.out.println("DOCUMENTO ALTERADO POR EL REGISTRADOR");
                                error_recibiendo = true;
                            }
                            if (error_recibiendo) {
                                System.out.println("No se ha guardado el fichero.");
                                new File(ruta_temp).delete();
                            }
                            Files.move(new File(ruta_temp).toPath(), new File(destino).toPath(), StandardCopyOption.REPLACE_EXISTING);
                            System.out.println("Se ha guardado el fichero en " + destino);
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
                    } catch (Exception ex) {
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
                        int numero_doc = 1;
                        if (confidenciales != null) {
                            System.out.println("\n\n\n\n***** DOCUMENTOS PRIVADOS *****\n"
                                    + "***************************************");
                            for (int i = 0; i < confidenciales.size(); i++) {
                                System.out.println("DOCUMENTO Nº" + numero_doc++);
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
                                System.out.println("DOCUMENTO Nº" + numero_doc++);
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
        System.setProperty("javax.net.ssl.keyStore", RAIZ + keyStore);
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePass);

        // Almacen de confianza
        System.setProperty("javax.net.ssl.trustStore", RAIZ + trustStore);
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

                ks.load(new FileInputStream(RAIZ + keyStore), contraseñaKeyStore);
                ts.load(new FileInputStream(RAIZ + trustStore), contraseñaTrustStore);

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

    private static X509Certificate getCertificate(String keyStore, String keyStorePwd, String aliasCertificate) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {

        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(new FileInputStream(keyStore), keyStorePwd.toCharArray());
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

    /**
     * Obtiene una ruta temporal no utilizada
     *
     * @return Ruta temporal
     */
    private static String getRutaTemporal() {
        String temp = "client_temp";
        long i = 0L;
        while (new File(temp + i).exists()) {
            i++;
        }
        return temp + i;
    }
}
