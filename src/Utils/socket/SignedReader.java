/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils.socket;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import javax.security.cert.CertificateException;

/**
 *
 * @author eryalus
 */
public class SignedReader extends SocketReader {

    /**
     * Se le pasa el socket creado por la conexión y genera y maneja el
     * inputstream. Solo se puede crear una instancia de esta clase por socket
     * ya que abre el inputstream.
     *
     * @param soc Socket
     * @throws IOException
     */
    public SignedReader(Socket soc) throws IOException {
        super(soc);
    }

    /**
     * Read a signed file from the input stream.
     *
     * @param dest_file the file to save the file. Probably a temporary file
     * @return Array of object[5]. 1st - String identificador 2nd - String
     * nombreDoc 3rd - Boolean Confidencialidad 4th String Archivo a guardar-5th byte[] firma  6th - X509Certificate certificado
     * @throws IOException if an I/O error occurs.
     * @throws NullPointerException if dest_file is null
     * @throws javax.security.cert.CertificateException If the certificate can
     * not be created.
     */
    public Object[] ReadSignedFile(File dest_file) throws IOException, NullPointerException, CertificateException {
        
        Object[] to_return = new Object[6];
        byte[] firma;
        String id, nombreDoc;
        boolean confidencialidad = false;
        
        OutputStream out = new FileOutputStream(dest_file); //primero lee el fichero y lo guarda en la ruta especificada.
        long longitud = readLong();
        byte[] bytes = new byte[1024];
        
        for (int i = 0; i < (longitud / 1024); i++) {
            in.read(bytes);
            out.write(bytes);
        }
        
        int resto = (int) (longitud - ((longitud / 1024) * 1024));
        bytes = new byte[resto];
        in.read(bytes);
        out.write(bytes);
        out.close();
        //ha terminado de leerlo y cierra el fichero en el que lo almacena.
        ArrayList<Byte> alfirma = new ArrayList<>();
        longitud = readLong();//se lee la firma y se almacena en un AL para ser pasado a un array posteriormente
        for (int i = 0; i < (longitud / 1024); i++) {
            in.read(bytes);
            for (Byte b : bytes) {
                alfirma.add(b);
            }
        }
        resto = (int) (longitud - ((longitud / 1024) * 1024));
        bytes = new byte[resto];
        in.read(bytes);
        for (Byte b : bytes) {
            alfirma.add(b);
        }
        firma = new byte[alfirma.size()]; //se pasa al array
        for (int index = 0; index < alfirma.size(); index++) {
            firma[index] = alfirma.get(index);
        }
        //se lee el identificador
        id = readString();
        //se lee el nombre del fichero
        nombreDoc = readString();
        //se lee la confidencialidad
        int temp = read();
        if (temp == 1) {
            confidencialidad = true;
        }
        //por último se lee la clave
        longitud = readLong();
        byte[] certificado = new byte[(int) longitud];
        read(certificado);
        
        
        to_return[0] = id;
        to_return[1] = nombreDoc;
        to_return[2] = confidencialidad;
        to_return[3] = dest_file.getName();
        to_return[4] = firma;
        to_return[5] = certificado;
        
        return to_return;
    }
    
     public Object[] ReadRecoveryRequest() throws IOException{
        
        Object[] to_return = new Object[2];
        
        //Primero leemos el id del documento que se nos pide recuperar
        String id = readString();
        
        //Leemos el certificado
        
        long longitud = readLong();
        
        byte[] cert = new byte[(int) longitud];
        
        read(cert);
        
        to_return[0] = id;
        to_return[1] = cert;
        
        return to_return;
        
    }
}
