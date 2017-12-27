/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package utils.socket;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 *
 * @author eryalus
 */
public class SocketWriter {

    private final OutputStream out;

    /**
     * Returns a writer for this socket. If this socket has an associated
     * channel then the resulting output stream delegates all of its operations
     * to the channel. If the channel is in non-blocking mode then the output
     * stream's write operations will throw an IllegalBlockingModeException.
     * Closing the returned SocketWriter will close the associated socket.
     *
     * @param soc The socket
     * @throws IOException
     */
    public SocketWriter(Socket soc) throws IOException {
        out = soc.getOutputStream();
    }

    /**
     * Write specified file to this output stream. It will write a long with the
     * number of bytes of the file and the the file as a array of bytes. {Long +
     * byte[]}
     *
     * @param path the file path.
     * @return false if the file doesn't exists.
     * @throws IOException if an I/O error occurs.
     */
    public boolean writeFile(String path) throws IOException {
        return writeFile(new File(path));
    }

    /**
     * Write specified file to this output stream. It will write a long with the
     * number of bytes of the file and the the file as a array of bytes. {Long +
     * byte[]}
     *
     * @param file the file.
     * @return false if the file doesn't exists.
     * @throws IOException if an I/O error occurs.
     */
    public boolean writeFile(File file) throws IOException {
        try {
            InputStream in = new FileInputStream(file);
            long longitud = file.length();
            writeLong(longitud);
            flush();
            byte[] bytes = new byte[1024];
            int leidos = 0;
            while ((leidos = in.read(bytes)) > 0) {
                write(Arrays.copyOfRange(bytes, 0, leidos));
            }
            flush();
            in.close();
            return true;
        } catch (FileNotFoundException ex) {
            return false;
        }
    }

    /**
     * Writes the specified byte to this output stream. The general contract for
     * write is that one byte is written to the output stream. The byte to be
     * written is the eight low-order bits of the argument b. The 24 high-order
     * bits of b are ignored.
     *
     * @param b the byte.
     * @throws IOException if an I/O error occurs;
     */
    public void write(int b) throws IOException {
        out.write(b);
    }

    /**
     * Write the specified long to this output stream.
     *
     * @param num the long.
     * @throws IOException if an I/O error occurs.
     */
    public void writeLong(long num) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(num);
        out.write(buffer.array());
    }

    /**
     * Write the specified String to this output stream.
     *
     * @param text the String.
     * @throws IOException if an I/O error occurs.
     */
    public void writeString(String text) throws IOException {
        writeInt32(text.getBytes().length);
        write(text.getBytes());
    }

    /**
     * Write the specified integer to this output stream.
     *
     * @param num the number.
     * @throws IOException if an I/O error occurs.
     */
    public void writeInt32(int num) throws IOException {
        byte[] send = new byte[4];
        send[0] = (byte) (num & 0x000000ff);
        send[1] = (byte) ((num & 0x0000ff00) >> 8);
        send[2] = (byte) ((num & 0x00ff0000) >> 16);
        send[3] = (byte) ((num & 0xff000000) >> 24);
        out.write(send);
    }

    /**
     * Write the specified integer to this output stream. The number to be
     * written is the sixteen low-order bits of the argument num. The sixteen
     * high-order bits of the number are ignored.
     *
     * @param num the number
     * @throws IOException if an I/O error occurs.
     */
    public void writeInt16(int num) throws IOException {
        short numero = (short) num;
        ByteBuffer buffer = ByteBuffer.allocate(Short.BYTES);
        buffer.putShort(numero);
        buffer.flip();
        out.write(buffer.array());
        /*
        byte[] send = new byte[2];
        send[0] = (byte) (num & 0x000000ff);
        send[1] = (byte) ((num & 0x0000ff00) >> 8);
        out.write(send);*/
    }

    /**
     * Writes b.length bytes from the specified byte array to this output
     * stream. The general contract for write(bytes) is that it should have
     * exactly the same effect as the call write(bytes, 0, b.length).
     *
     * @param bytes the data.
     * @throws IOException if an I/O error occurs.
     */
    public void write(byte[] bytes) throws IOException {
        out.write(bytes);
    }

    /**
     * Writes len bytes from the specified byte array starting at offset off to
     * this output stream. The general contract for write(b, off, len) is that
     * some of the bytes in the array b are written to the output stream in
     * order; element b[off] is the first byte written and b[off+len-1] is the
     * last byte written by this operation. The write method of OutputStream
     * calls the write method of one argument on each of the bytes to be written
     * out. Subclasses are encouraged to override this method and provide a more
     * efficient implementation. If b is null, a NullPointerException is thrown.
     * If off is negative, or len is negative, or off+len is greater than the
     * length of the array b, then an IndexOutOfBoundsException is thrown.
     *
     * @param b the data.
     * @param off the start offset in the data.
     * @param len the number of bytes to write.
     * @throws IOException if an I/O error occurs. In particular, an IOException
     * is thrown if the output stream is closed.
     */
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len);
    }

    /**
     * Flushes this writer and forces any buffered output bytes to be written
     * out. The general contract of flush is that calling it is an indication
     * that, if any bytes previously written have been buffered by the
     * implementation of the writer, such bytes should immediately be written to
     * their intended destination. If the intended destination of this stream is
     * an abstraction provided by the underlying operating system, for example a
     * file, then flushing the stream guarantees only that bytes previously
     * written to the stream are passed to the operating system for writing; it
     * does not guarantee that they are actually written to a physical device
     * such as a disk drive.
     *
     * @throws IOException if an I/O error occurs.
     */
    public void flush() throws IOException {
        out.flush();
    }

    /**
     * Closes this writer and releases any system resources associated with this
     * stream. The general contract of close is that it closes the writer. A
     * closed writer cannot perform write operations and cannot be reopened.
     *
     * @throws IOException if an I/O error occurs.
     */
    public void close() throws IOException {
        out.close();
    }

}
