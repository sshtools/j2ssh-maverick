package com.sshtools.ssh.components.jce;

public class DiffieHellmanGroupExchangeSha256 extends
		DiffieHellmanGroupExchangeSha1 {

	public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256 = "diffie-hellman-group-exchange-sha256";
	
	public DiffieHellmanGroupExchangeSha256() {
		super("SHA-256");
	}
	
	public String getAlgorithm() {
	    return DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256;
	}
}
