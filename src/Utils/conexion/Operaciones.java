package Utils.conexion;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;

import Utils.data.CSVHandler;
import Utils.socket.SignedReader;
import Utils.socket.SignedWriter;
import java.awt.HeadlessException;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

public class Operaciones {

    private SignedWriter signedWriter;
    private SignedReader signedReader;
    public static final int NO_OPERATION = 0;
    public static final int REGISTRAR = 1;
    public static final int RECUPERAR = 2;
    public static final int LISTAR = 3;
    public static final int READY = 255;

    public Operaciones(SignedWriter signedWriter, SignedReader signedReader) {
        super();
        this.signedWriter = signedWriter;
        this.signedReader = signedReader;
    }

    public void registrarDocumento(JFrame parent, String keyStore, String tipoClave, String clientCN, String keyStorePass, String docName, String docPath, boolean confidencialidad) throws IOException {

        byte[] sigRD = null;
        X509Certificate cert = null;
        try {
            String usuario = clientCN;
            sigRD = SSL_client.sign(docPath, keyStore, clientCN + "-firma-" + tipoClave);
            cert = SSL_client.getCertificate(keyStore, keyStorePass, clientCN + "-firma-" + tipoClave);

            /*-------- ESCRIBIMOS EL CÓDIGO DE OPERACIÓN ---------*/
            signedWriter.write(REGISTRAR);
            signedWriter.flush();

            if (signedReader.read() == NO_OPERATION) {
                JOptionPane.showMessageDialog(parent, "Operación no operativa en el servidor", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            signedWriter.SendSignedFile(usuario, docName, confidencialidad, docPath, sigRD, cert);

            String resultadoOP = signedReader.readString();

            if (resultadoOP.equalsIgnoreCase(SSL_client.OK)) {
                Object[] obs = signedReader.readRegisterResponse();
                Long idRegistro = (Long) obs[0];
                String sello = (String) obs[1];
                byte[] sigRD_recuperada = (byte[]) obs[2];
                byte[] certRAW = (byte[]) obs[3];
                if (!SSL_client.verifyCert(certRAW)) {
                    JOptionPane.showMessageDialog(parent, "CERTIFICADO DE REGISTRADOR INCORRECTO", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (!SSL_client.verify_sigRD(certRAW, docPath, sigRD_recuperada, sello, idRegistro, sigRD)) {
                    JOptionPane.showMessageDialog(parent, "FIRMA INCORRECTA DEL REGISTRADOR", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (!new CSVHandler().newEntry(idRegistro, SSL_client.getSHA512(docPath))) {
                    JOptionPane.showMessageDialog(parent, "NO SE HA PODIDO ALMACENAR EL SHA512", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                new File(docPath).delete();
                JOptionPane.showMessageDialog(parent, "\n****** REGISTRO CORRECTO *******\n"
                        + "Atención! A continuación se muestra el identificador de documento.\n Guardelo si desea recuperar en un futuro el docuento registrado!"
                        + "\nEl ID de su registro es: \n\n"
                        + "********************************************\n"
                        + "*         " + idRegistro + "                                *\n"
                        + "********************************************", "Éxito", JOptionPane.INFORMATION_MESSAGE);

            } else {
                JOptionPane.showMessageDialog(parent, "Error desconocido", "Error", JOptionPane.ERROR_MESSAGE);

            }

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException | InvalidKeyException | SignatureException | CertificateException ex) {
            JOptionPane.showMessageDialog(parent, "Error desconocido", "Error", JOptionPane.ERROR_MESSAGE);

        }
    }

    public void recuperarDocumento(JFrame parent, String keyStore, String keyStorePass, String clientCN, String tipoClave, Long idRegistro) throws IOException {

        try {
            //  -------- ESCRIBIMOS EL CÓDIGO DE OPERACIÓN ---------
            signedWriter.write(RECUPERAR);
            signedWriter.flush();

            if (signedReader.read() == NO_OPERATION) {
                JOptionPane.showMessageDialog(parent, "Operación no operativa en el servidor", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            X509Certificate cert = SSL_client.getCertificate(keyStore, keyStorePass, clientCN + "-auth-" + tipoClave);
            boolean sendOk = signedWriter.sendRecoveryRequest("" + idRegistro, cert);
            if (!sendOk) {
                JOptionPane.showMessageDialog(parent, "Error enviando el identificador y el certificado", "Error", JOptionPane.ERROR_MESSAGE);

                return;

            }
            String documentStatus = signedReader.readString();
            if (documentStatus.equals("DOCUMENTO INEXISTENTE")) {
                JOptionPane.showMessageDialog(parent, "DOCUMENTO INEXISTENTE", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            String confidencial = signedReader.readString();

            if (confidencial.equals("PUBLICO")) {

                String ruta_temp = getRutaTemporal();

                Object[] datos = signedReader.ReadRecoveryResponse(new File(ruta_temp));

                String destino = "Recibido/";
                String nombre_fichero = (String) datos[5];
                boolean error_recibiendo = false;
                if (!DatatypeConverter.printHexBinary(new CSVHandler().getSHA512(idRegistro)).equals(DatatypeConverter.printHexBinary(SSL_client.getSHA512(ruta_temp)))) {
                    JOptionPane.showMessageDialog(parent, "DOCUMENTO ALTERADO POR EL REGISTRADOR", "Error", JOptionPane.ERROR_MESSAGE);
                    error_recibiendo = true;
                }
                destino += nombre_fichero;
                if (error_recibiendo) {
                    JOptionPane.showMessageDialog(parent, "No se ha guardado el fichero.", "Error", JOptionPane.ERROR_MESSAGE);
                    new File(ruta_temp).delete();
                }
                Files.move(new File(ruta_temp).toPath(), new File(destino).toPath(), StandardCopyOption.REPLACE_EXISTING);
                JOptionPane.showMessageDialog(parent, "Se ha guardado el fichero en " + destino, "Éxito", JOptionPane.INFORMATION_MESSAGE);

            } else {

                String resultadoOP = signedReader.readString();
                if (resultadoOP.equalsIgnoreCase(SSL_client.FAIL_CERT)) {
                    System.out.println(SSL_client.FAIL_CERT);
                } else if (resultadoOP.equalsIgnoreCase(SSL_client.FAIL_SIGN)) {
                    System.out.println(SSL_client.FAIL_SIGN);
                } else {
                    System.out.println("\n****** CERTIFICADO CORRECTO *******");
                }

                String acceso = signedReader.readString();
                System.out.println(acceso);
                if (acceso.equals("ACCESO NO PERMITIDO")) {
                    JOptionPane.showMessageDialog(parent, "ACCESO NO PERMITIDO", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                String ruta_temp = getRutaTemporal();

                Object[] datos = signedReader.ReadRecoveryResponse(new File(ruta_temp));
                String sello = (String) datos[2];
                Long id_registro_leido = Long.parseLong((String) datos[1]);
                String destino = "Recibido/";
                String nombre_fichero = (String) datos[5];
                destino += nombre_fichero;

                byte[] firma_registrador = (byte[]) datos[3];
                byte[] cert_server = (byte[]) datos[4];
                boolean error_recibiendo = false;
                if (!SSL_client.verifyCert(cert_server)) {
                    JOptionPane.showMessageDialog(parent, "CERTIFICADO SERVIDOR NO VALIDO", "Error", JOptionPane.ERROR_MESSAGE);

                    error_recibiendo = true;
                } else {
                    JOptionPane.showMessageDialog(parent, "CERTIFICADO SERVIDOR CORRECTO", "Éxito", JOptionPane.INFORMATION_MESSAGE);

                }
                byte[] firma_propia = SSL_client.sign(ruta_temp, keyStore, clientCN + "-firma-" + tipoClave);
                if (!SSL_client.verify_sigRD(cert_server, ruta_temp, firma_registrador, sello, id_registro_leido, firma_propia)) {
                    JOptionPane.showMessageDialog(parent, "FALLO DE FIRMA DEL REGISTRADOR", "Error", JOptionPane.ERROR_MESSAGE);

                    error_recibiendo = true;
                } else {
                    JOptionPane.showMessageDialog(parent, "FIRMA DEL REGISTRADOR CORRECTA", "Éxito", JOptionPane.INFORMATION_MESSAGE);

                }

                if (!DatatypeConverter.printHexBinary(new CSVHandler().getSHA512(idRegistro)).equals(DatatypeConverter.printHexBinary(SSL_client.getSHA512(ruta_temp)))) {
                    JOptionPane.showMessageDialog(parent, "DOCUMENTO ALTERADO POR EL REGISTRADOR", "Error", JOptionPane.ERROR_MESSAGE);
                    error_recibiendo = true;
                }
                if (error_recibiendo) {
                    JOptionPane.showMessageDialog(parent, "No se ha guardado el fichero.", "Error", JOptionPane.ERROR_MESSAGE);
                    new File(ruta_temp).delete();
                }
                Files.move(new File(ruta_temp).toPath(), new File(destino).toPath(), StandardCopyOption.REPLACE_EXISTING);
                JOptionPane.showMessageDialog(parent, "Se ha guardado el fichero en " + destino, "Éxito", JOptionPane.INFORMATION_MESSAGE);

            }

        } catch (IOException | HeadlessException | KeyStoreException | NoSuchAlgorithmException | CertificateException | NumberFormatException | UnrecoverableEntryException | InvalidKeyException | SignatureException ex) {
            JOptionPane.showMessageDialog(parent, "Error desconocido", "Error", JOptionPane.ERROR_MESSAGE);
        }

    }

    public void listarDocumento(JFrame parent, String keyStore, String keyStorePass, String clientCN, String tipoClave, JTable tabla) {

        try {
            DefaultTableModel dtm = (DefaultTableModel) tabla.getModel();

            //-------- ESCRIBIMOS EL CÓDIGO DE OPERACIÓN ---------
            signedWriter.write(LISTAR);
            signedWriter.flush();

            if (signedReader.read() == NO_OPERATION) {
                JOptionPane.showMessageDialog(parent, "Operación no operativa en el servidor", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            System.out.println(clientCN + "-auth-" + tipoClave);
            X509Certificate cert = SSL_client.getCertificate(keyStore, keyStorePass, clientCN + "-auth-" + tipoClave);

            boolean sendOk = signedWriter.sendDocumentListRequest(cert);

            if (!sendOk) {
                JOptionPane.showMessageDialog(parent, "Error el certificado de autenticación del cliente", "Error", JOptionPane.ERROR_MESSAGE);

                System.exit(0);

            }

            String resultadoOP = signedReader.readString();

            if (resultadoOP.equalsIgnoreCase(SSL_client.FAIL_CERT)) {
                JOptionPane.showMessageDialog(parent, SSL_client.FAIL_CERT, "Error", JOptionPane.ERROR_MESSAGE);

            }

            ArrayList<Object[]> confidenciales = signedReader.ReadListDocumentsRequest();
            ArrayList<Object[]> noConfidenciales = signedReader.ReadListDocumentsRequest();
            int numero_doc = 1;
            if (confidenciales != null) {
                System.out.println("\n\n\n\n***** DOCUMENTOS PRIVADOS *****\n"
                        + "***************************************");
                for (int i = 0; i < confidenciales.size(); i++) {
                    dtm.addRow(new Object[]{"Privado", String.valueOf((long) confidenciales.get(i)[0]), (String) confidenciales.get(i)[1], (String) confidenciales.get(i)[2], (String) confidenciales.get(i)[3]});

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
                    dtm.addRow(new Object[]{"Privado", String.valueOf((long) noConfidenciales.get(i)[0]), (String) noConfidenciales.get(i)[1], (String) noConfidenciales.get(i)[2], (String) noConfidenciales.get(i)[3]});

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
            tabla.setModel(dtm);
        } catch (FileNotFoundException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException ex) {
            Logger.getLogger(SSL_client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
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
