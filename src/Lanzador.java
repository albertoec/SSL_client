
import Utils.conexion.SSL_client;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author eryalus
 */
public class Lanzador {

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Uso: SSL_client keyStoreFile trustStoreFile");
            System.exit(0);
        }
        String keyStore = args[0].trim();
        String trustStore = args[1].trim();
        SSL_client ssl_client = new SSL_client(keyStore, trustStore);

    }
}
