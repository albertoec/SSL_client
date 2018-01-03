/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils.time;

import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 *
 * @author eryalus
 */
public class Calendario extends GregorianCalendar {

    private String addCeros(String txt, int tamaño) {
        int toadd = tamaño - txt.length();
        if (toadd > 0) {
            String temp = "";
            for (int i = 0; i < toadd; i++) {
                temp += "0";
            }
            temp += txt;
            return temp;
        } else {
            return txt;
        }
    }

    public Calendario(long time) {
        super();
        super.setTimeInMillis(time);
    }

    public Calendario() {
        super();
        super.setTimeInMillis(Calendar.getInstance().getTimeInMillis());
    }

    public String Fecha() {
        return super.get(Calendar.YEAR) + "/" + addCeros("" + super.get(Calendar.MONTH), 2) + "/" + addCeros("" + super.get(Calendar.DAY_OF_MONTH), 2) + " " + addCeros("" + super.get(Calendar.HOUR_OF_DAY), 2) + ":" + addCeros("" + super.get(Calendar.MINUTE), 2) + ":" + addCeros("" + super.get(Calendar.SECOND), 2);
    }

    @Override
    public String toString() {
        return "[" + super.get(Calendar.YEAR) + "/" + addCeros("" + super.get(Calendar.MONTH), 2) + "/" + addCeros("" + super.get(Calendar.DAY_OF_MONTH), 2) + " "
                + addCeros("" + super.get(Calendar.HOUR_OF_DAY), 2) + ":" + addCeros("" + super.get(Calendar.MINUTE), 2) + ":" + addCeros("" + super.get(Calendar.SECOND), 2) + "-"
                + addCeros("" + super.get(Calendar.MILLISECOND), 3) + "]";
    }
}
