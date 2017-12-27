/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package utils.socket;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;

/**
 *
 * @author eryalus
 */
public class SocketReader {

    protected final InputStream in;

    /**
     * Returns an reader for this socket. If this socket has an associated
     * channel then the resulting input stream delegates all of its operations
     * to the channel. If the channel is in non-blocking mode then the input
     * stream's read operations will throw an IllegalBlockingModeException.
     * Under abnormal conditions the underlying connection may be broken by the
     * remote host or the network software (for example a connection reset in
     * the case of TCP connections). When a broken connection is detected by the
     * network software the following applies to the returned input stream :-
     * The network software may discard bytes that are buffered by the socket.
     * Bytes that aren't discarded by the network software can be read using
     * read. If there are no bytes buffered on the socket, or all buffered bytes
     * have been consumed by read, then all subsequent calls to read will throw
     * an IOException. If there are no bytes buffered on the socket, and the
     * socket has not been closed using close, then available will return 0.
     * Closing the returned InputStream will close the associated socket.
     *
     * @param soc The socket
     * @throws IOException IOException - if an I/O error occurs when creating
     * the input stream, the socket is closed, the socket is not connected, or
     * the socket input has been shutdown using Socket.shutdownInput()
     */
    public SocketReader(Socket soc) throws IOException {
        in = soc.getInputStream();
    }

    /**
     * Read a file from the input stream. For being correctly readed the format
     * of data must be the number of bytes to read writed in a 64bit int (a
     * long) and then the bytes of the text. {Long + bytes}
     *
     * @param dest_path the path of the file to save the file.
     * @return false if the file couldn't be created. true otherwise.
     * @throws IOException if an I/O error occurs.
     * @throws NullPointerException if dest_path is null
     */
    public boolean readFile(String dest_path) throws IOException, NullPointerException {
        File file = new File(dest_path);
        return readFile(file);
    }

    /**
     * Read a file from the input stream. For being correctly readed the format
     * of data must be the number of bytes to read writed in a 64bit int (a
     * long) and then the bytes of the text. {Long + bytes}
     *
     * @param dest_file the file to save the file.
     * @return false if the file couldn't be created. true otherwise.
     * @throws IOException if an I/O error occurs.
     * @throws NullPointerException if dest_file is null
     */
    public boolean readFile(File dest_file) throws IOException, NullPointerException {
        try {
            OutputStream out = new FileOutputStream(dest_file);
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
            return true;
        } catch (FileNotFoundException ex) {
            return false;
        }
    }

    /**
     * Reads the next byte of data from the input stream. The value byte is
     * returned as an int in the range 0 to 255. If no byte is available because
     * the end of the stream has been reached, the value -1 is returned. This
     * method blocks until input data is available, the end of the stream is
     * detected, or an exception is thrown.
     *
     * @return the next byte of data, or -1 if the end of the stream is reached.
     * @throws IOException if an I/O error occurs.
     */
    public int read() throws IOException {
        return in.read();
    }

    /**
     * Reads some number of bytes from the input stream and stores them into the
     * buffer array b. The number of bytes actually read is returned as an
     * integer. This method blocks until input data is available, end of file is
     * detected, or an exception is thrown. If the length of b is zero, then no
     * bytes are read and 0 is returned; otherwise, there is an attempt to read
     * at least one byte. If no byte is available because the stream is at the
     * end of the file, the value -1 is returned; otherwise, at least one byte
     * is read and stored into b. The first byte read is stored into element
     * b[0], the next one into b[1], and so on. The number of bytes read is, at
     * most, equal to the length of b. Let k be the number of bytes actually
     * read; these bytes will be stored in elements b[0] through b[k-1], leaving
     * elements b[k] through b[b.length-1] unaffected. The read(b) method for
     * class SocketReader has the same effect as: read(b, 0, b.length)
     *
     * @param bytes the buffer into which the data is read.
     * @return the total number of bytes read into the buffer, or -1 if there is
     * no more data because the end of the stream has been reached.
     * @throws IOException If the first byte cannot be read for any reason other
     * than the end of the file, if the input stream has been closed, or if some
     * other I/O error occurs.
     * @throws NullPointerException if b is null.
     */
    public int read(byte[] bytes) throws IOException, NullPointerException {
        return in.read(bytes);
    }

    /**
     * Reads up to len bytes of data from the input stream into an array of
     * bytes. An attempt is made to read as many as len bytes, but a smaller
     * number may be read. The number of buytes actually read is returned as an
     * integer. This method blocks until input data is available, end of file is
     * detected, or an exception is thrown. If len is zero, then no bytes are
     * read and 0 is returned; otherwise, there is an attempt to read at least
     * one byte. If no byte is available because the stream is at end of file,
     * the value -1 is returned; otherwise, at least one byte is read and stored
     * into b. The first byte read is stored into element b[off], the next one
     * into b[off+1], and so on. The number of bytes read is, at most, equal to
     * len. Let k be the number of bytes actually read; these bytes will be
     * stored in elements b[off] through b[off+k-1], leaving elements b[off+k]
     * through b[off+len-1] unaffected. In every case, elements b[0] through
     * b[off] and elements b[off+len] through b[b.length-1] are unaffected. The
     * read(b, off, len) method for class InputStream simply calls the method
     * read() repeatedly. If the first such call results in an IOException, that
     * exception is returned from the call to the read(b, off, len) method. If
     * any subsequent call to read() results in a IOException, the exception is
     * caught and treated as if it were end of file; the bytes read up to that
     * point are stored into b and the number of bytes read before the exception
     * occurred is returned. The default implementation of this method blocks
     * until the requested amount of input data len has been read, end of file
     * is detected, or an exception is thrown.
     *
     * @param bytes the buffer into which the data is read.
     * @param off the start offset in array b at which the data is written.
     * @param len the maximum number of bytes to read.
     * @return the total number of bytes read into the buffer, or -1 if there is
     * no more data because the end of the stream has been reached.
     * @throws IOException If the first byte cannot be read for any reason other
     * than end of file, or if the input stream has been closed, or if some
     * other I/O error occurs.
     * @throws NullPointerException If b is null.
     * @throws IndexOutOfBoundsException If off is negative, len is negative, or
     * len is greater than b.length - off
     */
    public int read(byte[] bytes, int off, int len) throws IOException, NullPointerException, IndexOutOfBoundsException {
        return in.read(bytes, off, len);
    }

    /**
     * Reads the next String from the input stream. For being correctly readed
     * the format of data must be the number of bytes to read writed in a 32bit
     * int and then the bytes of the text. {Integer32 + bytes}
     *
     * @return the writed String readed from the input stream
     * @throws IOException if an I/O error occurs.
     */
    public String readString() throws IOException {
        int longitud = readInt32();
        byte[] bytes = new byte[longitud];
        read(bytes);
        return new String(bytes);
    }

    /**
     * Read the next 64 bits and return them as a long.
     *
     * @return the next 64bits as a long
     * @throws IOException if an I/O error occurs.
     */
    public long readLong() throws IOException {
        byte[] bytes = new byte[8];
        in.read(bytes);
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(bytes);
        buffer.flip();//need flip 
        return buffer.getLong();
    }

    /**
     * Read the next 16 bits and return them as a int
     *
     * @return the next 16bits as a int
     * @throws IOException if an I/O error occurs.
     */
    public int readInt16() throws IOException {
        byte[] nums = new byte[2];
        in.read(nums);
        ByteBuffer buffer = ByteBuffer.allocate(Short.BYTES);
        buffer.put(nums);
        buffer.flip();//need flip 
        return buffer.getShort();
    }

    /**
     * Read the next 16 bits and return them as a short
     *
     * @return the next 16bits as a short
     * @throws IOException if an I/O error occurs.
     */
    public short readShort() throws IOException{
        return (short) readInt16();
    }
    
    /**
     * Read the next 32 bits and return them as a int
     *
     * @return the next 32bits as a int
     * @throws IOException if an I/O error occurs.
     */
    public int readInt32() throws IOException {
        byte[] nums = new byte[4];
        in.read(nums);
        int i = ((nums[3] & 0x000000ff) << 24)
                | ((nums[2] & 0x000000ff) << 16)
                | ((nums[1] & 0x000000ff) << 8)
                | (nums[0] & 0x000000ff);
        return i;
    }

    /**
     * Closes this input stream and releases any system resources associated
     * with the stream.
     *
     * @throws IOException if an I/O error occurs.
     */
    public void close() throws IOException {
        in.close();
    }
    
    
}
