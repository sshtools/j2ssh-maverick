package com.sshtools.ssh;

import java.io.IOException;

/**
 * <p>This interface adds timeout support to the {@see SocketTransport} interface.</p>
 *
 * @author Lee David Painter
 */
public interface SocketTimeoutSupport {

        /**
         * Set the socket timeout in milliseconds.
         * @param timeout int
         * @throws IOException
         */
        public void setSoTimeout(int timeout) throws IOException;

        /**
         * Get the current socket timeout in milliseconds.
         * @return int
         * @throws IOException
         */
        public int getSoTimeout() throws IOException;
}
