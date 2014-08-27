
package com.sshtools.util;

//import java.io.FileFilter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 *
 *
 * @author $author$
 */
public class IOUtil {

    /**
     * Default buffer size for stream utility methods
     */
    public static int BUFFER_SIZE = 8192;

    /**
     * Copy from an input stream to an output stream. It is up to the caller to
     * close the streams.
     * 
     * @param in input stream
     * @param out output stream
     * @throws IOException on any error
     */
    public static void copy(InputStream in, OutputStream out) throws IOException {
        copy(in, out, -1);
    }


    /**
     * Copy the specified number of bytes from an input stream to an output
     * stream. It is up to the caller to close the streams.
     * 
     * @param in input stream
     * @param out output stream
     * @param count number of bytes to copy
     * @throws IOException on any error
     */
    public static void copy(InputStream in, OutputStream out, long count) throws IOException {
    	copy(in, out, count, BUFFER_SIZE);
    }

    /**
     * Copy the specified number of bytes from an input stream to an output
     * stream. It is up to the caller to close the streams.
     * 
     * @param in input stream
     * @param out output stream
     * @param count number of bytes to copy
     * @param bufferSize buffer size
     * @throws IOException on any error
     */
    public static void copy(InputStream in, OutputStream out, long count, int bufferSize) throws IOException {
        byte buffer[] = new byte[bufferSize];
        int i = bufferSize;
        if (count >= 0) {
            while (count > 0) {
                if (count < bufferSize)
                    i = in.read(buffer, 0, (int) count);
                else
                    i = in.read(buffer, 0, bufferSize);

                if (i == -1)
                    break;

                count -= i;
                out.write(buffer, 0, i);
            }
        } else {
            while (true) {
                i = in.read(buffer, 0, bufferSize);
                if (i < 0)
                    break;
                out.write(buffer, 0, i);
            }
        }
    }
  /**
   *
   *
   * @param in
   *
   * @return
   */
  public static boolean closeStream(InputStream in) {
    try {
      if (in != null) {
        in.close();
      }

      return true;
    }
    catch (IOException ioe) {
      return false;
    }
  }

  /**
   *
   *
   * @param out
   *
   * @return
   */
  public static boolean closeStream(OutputStream out) {
    try {
      if (out != null) {
        out.close();
      }

      return true;
    }
    catch (IOException ioe) {
      return false;
    }
  }

  public static boolean delTree(File file) {
    if (file.isFile()) {
      return file.delete();
    }
	String[] list = file.list();
      for (int i = 0; i < list.length; i++) {
        if (!delTree(new File(file, list[i]))) {
          return false;
        }
      }
    return true;
  }

  public static void recurseDeleteDirectory(File dir) {

    String[] files = dir.list();

    if (files == null) {
      return; // Directory could not be read
    }

    for (int i = 0; i < files.length; i++) {
      File f = new File(dir, files[i]);

      if (f.isDirectory()) {
        recurseDeleteDirectory(f);

      }
      f.delete();
    }

    dir.delete();

  }

  public static void copyFile(File from, File to) throws IOException {

    if (from.isDirectory()) {
      if (!to.exists()) {
        to.mkdir();
      }
      String[] children = from.list();
      for (int i = 0; i < children.length; i++) {
        File f = new File(from, children[i]);
        if (f.getName().equals(".")
            || f.getName().equals("..")) {
          continue;
        }
        if (f.isDirectory()) {
          File f2 = new File(to, f.getName());
          copyFile(f, f2);
        }
        else {
          copyFile(f, to);
        }
      }
    }
    else if (from.isFile() && (to.isDirectory() || to.isFile())) {
      if (to.isDirectory()) {
        to = new File(to, from.getName());
      }
      FileInputStream in = new FileInputStream(from);
      FileOutputStream out = new FileOutputStream(to);
      byte[] buf = new byte[32678];
      int read;
      while ( (read = in.read(buf)) > -1) {
        out.write(buf, 0, read);
      }
      closeStream(in);
      closeStream(out);

    }
  }

}
