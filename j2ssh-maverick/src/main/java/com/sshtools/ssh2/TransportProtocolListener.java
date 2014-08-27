package com.sshtools.ssh2;

public interface TransportProtocolListener {

	public void onDisconnect(String msg, int reason);
	
	public void onIdle(long lastActivity);
}
