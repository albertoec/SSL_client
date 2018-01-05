/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils.data;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author eryalus
 */
public class CSVHandler {

    private static final String PATH = "datos.csv";

    /**
     * obtiene el SHA512 del fichero registrado asociado a ese idRegistro
     *
     * @param idRegistro
     * @return el SHA512 o null en caso de no encontrarlo
     */
    public byte[] getSHA512(Long idRegistro) {
        try {
            File fichero = new File(PATH);
            BufferedReader br = new BufferedReader(new FileReader(fichero));
            String linea;
            while ((linea = br.readLine()) != null) {
                String partes[] = linea.split(",");
                if (Long.parseLong(partes[0]) == idRegistro) {
                    br.close();
                    return DatatypeConverter.parseHexBinary(partes[1]);
                }
            }
            br.close();
        } catch (IOException ex) {
        }
        return null;
    }

    /**
     * Añade una nueva entrada para un idRegistro
     *
     * @param idRegistro
     * @param SHA512
     * @return true si se añade correctamente o false en otro caso
     */
    public boolean newEntry(Long idRegistro, byte[] SHA512) {
        try {
            File fichero = new File(PATH);
            BufferedWriter bw = new BufferedWriter(new FileWriter(fichero, true));
            bw.write(idRegistro + "," + DatatypeConverter.printHexBinary(SHA512) + "\n");
            bw.close();
            return true;
        } catch (IOException ex) {
        }
        return false;
    }
}
