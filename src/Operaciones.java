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

	public void registrarDocumento(BufferedReader buffer,String keyStore, String tipoClave,String clientCN,String keyStorePass) throws IOException{

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
        	System.out.println(keyStore+clientCN+tipoClave);
            sigRD = SSL_client.sign(documento, keyStore, clientCN + "-firma-" + tipoClave);
            cert = SSL_client.getCertificate(keyStore, keyStorePass, clientCN + "-firma-" + tipoClave);

            /*-------- ESCRIBIMOS EL CÓDIGO DE OPERACIÓN ---------*/

            signedWriter.write(REGISTRAR);
            signedWriter.flush();

            if (signedReader.read() == NO_OPERATION) {
                System.out.println("Operación no operativa en el servidor");
                System.exit(0);
            }

            System.out.println(cert.getIssuerDN().getName());
            signedWriter.SendSignedFile(id_propietario, nombreDoc, confidencialidad, documento, sigRD, cert);

            String resultadoOP = signedReader.readString();

            if (resultadoOP.equalsIgnoreCase(SSL_client.OK)) {
                Object[] obs = signedReader.readRegisterResponse();
                Long idRegistro = (Long) obs[0];
                String sello = (String) obs[1];
                byte[] sigRD_recuperada = (byte[]) obs[2];
                byte[] certRAW = (byte[]) obs[3];
                if (!SSL_client.verifyCert(certRAW)) {
                    System.out.println("CERTIFICADO DE REGISTRADOR INCORRECTO");
                    return;
                }
                if (!SSL_client.verify_sigRD(certRAW, documento, sigRD_recuperada, sello, idRegistro, sigRD)) {
                    System.out.println("FIRMA INCORRECTA DEL REGISTRADOR");
                    return;
                }
                if (!new CSVHandler().newEntry(idRegistro, SSL_client.getSHA512(documento))) {
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
	}
	
	
	
	
	public void recuperarDocumento(BufferedReader buffer,String keyStore,String keyStorePass,String clientCN,String tipoClave) throws IOException{
		 System.out.println("********************************************");
         System.out.println("*          RECUPERAR DOCUMENTO             *");
         System.out.println("********************************************");
         
         Boolean error = false;
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
           //  -------- ESCRIBIMOS EL CÓDIGO DE OPERACIÓN ---------
             signedWriter.write(RECUPERAR);
             signedWriter.flush();

             if (signedReader.read() == NO_OPERATION) {
                 System.out.println("Operación no operativa en el servidor");
                 System.exit(0);
             }
             X509Certificate cert = SSL_client.getCertificate(keyStore, keyStorePass, clientCN + "-auth-" + tipoClave);

             boolean sendOk = signedWriter.sendRecoveryRequest(id_registro, cert);

             if (!sendOk) {

                 System.out.println("Error enviando el identificador y el certificado");
                 System.exit(0);

             }

             String documentStatus = signedReader.readString();

             if (documentStatus.equals("DOCUMENTO INEXISTENTE")) {
                 System.out.println(documentStatus);
                 System.exit(0);
             }

             String confidencial = signedReader.readString();

             System.out.println(confidencial);

             if (confidencial.equals("PUBLICO")) {

                 String ruta_temp = getRutaTemporal();

                 Object[] datos = signedReader.ReadRecoveryResponse(new File(ruta_temp));

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
                     System.exit(0);
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
                     System.out.println("CERTIFICADO SERVIDOR NO VALIDO");
                     error_recibiendo = true;
                 } else {
                     System.out.println("CERTIFICADO SERVIDOR CORRECTO");
                 }
                 byte[] firma_propia = SSL_client.sign(ruta_temp, keyStore, clientCN + "-firma-" + tipoClave);
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

	}
	public void listarDocumento(BufferedReader buffer,String keyStore,String keyStorePass,String clientCN,String tipoClave){
	     System.out.println("********************************************");
         System.out.println("*          LISTAR DOCUMENTOS               *");
         System.out.println("********************************************");

         try {

             //-------- ESCRIBIMOS EL CÓDIGO DE OPERACIÓN ---------
             signedWriter.write(LISTAR);
             signedWriter.flush();

             if (signedReader.read() == NO_OPERATION) {
                 System.out.println("Operación no operativa en el servidor");
                 System.exit(0);
             }

             System.out.println(clientCN + "-auth-" + tipoClave);
             X509Certificate cert = SSL_client.getCertificate(keyStore, keyStorePass, clientCN + "-auth-" + tipoClave);

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
