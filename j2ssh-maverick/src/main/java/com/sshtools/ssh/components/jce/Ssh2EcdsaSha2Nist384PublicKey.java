package com.sshtools.ssh.components.jce;


public class Ssh2EcdsaSha2Nist384PublicKey extends Ssh2EcdsaSha2NistPublicKey {

	public Ssh2EcdsaSha2Nist384PublicKey() {
		super("ecdsa-sha2-nistp384", "SHA384/ECDSA", "secp384r1");
	}
}
