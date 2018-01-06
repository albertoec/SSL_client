/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils.conexion;

import java.io.FileInputStream;
import java.security.KeyStore;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 *
 * @author eryalus
 */
public class metodos {

    private static final int PORT = 8080;
    private final String keyStore, trustStore;

    public static int getPORT() {
        return PORT;
    }

    public String getKeyStore() {
        return keyStore;
    }

    public String getTrustStore() {
        return trustStore;
    }

    private String keyStorePass, trustStorePass, clientCN, tipoClave, ipServidor;

    public String getKeyStorePass() {
        return keyStorePass;
    }

    public void setKeyStorePass(String keyStorePass) {
        this.keyStorePass = keyStorePass;
    }

    public String getTrustStorePass() {
        return trustStorePass;
    }

    public void setTrustStorePass(String trustStorePass) {
        this.trustStorePass = trustStorePass;
    }

    public String getClientCN() {
        return clientCN;
    }

    public void setClientCN(String clientCN) {
        this.clientCN = clientCN;
    }

    public String getTipoClave() {
        return tipoClave;
    }

    public void setTipoClave(String tipoClave) {
        this.tipoClave = tipoClave;
    }

    public String getIpServidor() {
        return ipServidor;
    }

    public void setIpServidor(String ipServidor) {
        this.ipServidor = ipServidor;
    }

    public metodos(String keyStore, String trusStore) {
        this.keyStore = keyStore;
        this.trustStore = trusStore;
    }

    /**
     * ****************************************************
     * getServerSocketFactory(String type) {}
     *
     * *************************************************** @param type
     * @return
     */
    public SocketFactory getServerSocketFactory(String type) {

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

                ks.load(new FileInputStream(keyStore), contraseñaKeyStore);
                ts.load(new FileInputStream(trustStore), contraseñaTrustStore);

                kmf.init(ks, contraseñaKeyStore);
                tmf.init(ts);
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

                ssf = ctx.getSocketFactory();

                return ssf;

            } catch (Exception e) {

                e.printStackTrace();
            }

        } else {
           //Usando la Factoria socket por defecto (no SSL)

            return SocketFactory.getDefault();
        }

        return null;
    }
}
