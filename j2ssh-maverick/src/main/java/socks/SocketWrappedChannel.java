package socks;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import com.sshtools.ssh.SshChannel;

public class SocketWrappedChannel extends Socket {

	SshChannel channel;
	SocketWrappedChannel(SshChannel channel) {
		this.channel = channel;
	}
	
	public InputStream getInputStream() throws IOException {
		return channel.getInputStream();
	}
	
	public OutputStream getOutputStream() throws IOException {
		return channel.getOutputStream();
	}
	
	public void close() throws IOException {
		channel.close();
	}
}
