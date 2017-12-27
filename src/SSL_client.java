
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

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
    private static final String RAIZ = "/home/expploitt/";
    private static String keyStore, trustStore;

    private static String keyStorePass, trustStorePass;

    public static void main(String[] args) {

        try {

            BufferedReader buffer = new BufferedReader(new InputStreamReader(System.in));

            if (args.length != 2) {
                System.out.println("Uso: SSL_client keyStoreFile trustStoreFile");
                System.exit(0);
            }

            keyStore = args[0].trim();
            trustStore = args[1].trim();

            System.out.print("Introduzca la contraseña del keyStore: ");
            System.out.print("> ");
            keyStorePass = buffer.readLine();

            System.out.print("Introduzca la contraseña del trustStore: ");
            System.out.print("> ");
            trustStorePass = buffer.readLine();

            new SSL_client().definirKeyStores();

            SSLSocketFactory socketFactory = (SSLSocketFactory) SSL_client.getServerSocketFactory("TLS");
            SSLSocket socket = (SSLSocket) socketFactory.createSocket(HOST, PORT);

            String[] suites = socket.getSupportedCipherSuites();
            System.out.println("\n***** SELECCIONE UNA CYPHER SUYTE ***** \n");

            for (int i = 0; i < suites.length; i++) {
                System.out.println((i + 1) + ".-" + suites[i]);
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

        } catch (IOException ex) {
            Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public void mainMenu(BufferedReader bf) throws IOException {

        System.out.println("********************************************");
        System.out.println("* Bienvenido a Watermelon SSL/TLS Register *");
        System.out.println("********************************************");

        System.out.println("1) Registrar documento");
        System.out.println("2) Recuperar documento");
        System.out.println("3) Salir");

        System.out.println("¿Qué desea hacer?");
        System.out.print("> ");

        switch (bf.readLine()) {
            case "1":

                System.out.println("********************************************");
                System.out.println("*          REGISTRAR DOCUMENTO             *");
                System.out.println("********************************************");
                System.out.println("\nUso: \n"
                        + "id_propietario:           example@alumnos.uvigo.es \n"
                        + "nombreDoc:                nombre de fichero (100 caract. max.)\n "
                        + "tipoConfidencialidad:     PRIVADO/PUBLICO \n"
                        + "documento:                documento a registrar \n"
                        + "firmaDoc:                 firma del propietario sobre el documento (rsa o dsa) \n"
                        + "CertFirma(c):             cert. KP de firma del propietario \n");

                String entrada = bf.readLine();
                String[] partes = entrada.split("\\s+");

                break;

            case "2":
                break;

            default:
                System.out.println("Saliendo de la aplicación...");
                System.exit(0);
        }
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
    private static SocketFactory getServerSocketFactory(String type){

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

}
