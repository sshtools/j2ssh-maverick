package com.sshtools.ssh.components.jce;

public class DiffieHellmanEcdhNistp521 extends DiffieHellmanEcdh {

	public DiffieHellmanEcdhNistp521() {
		super("ecdh-sha2-nistp521", "secp521r1", "SHA-512");
	}

}
