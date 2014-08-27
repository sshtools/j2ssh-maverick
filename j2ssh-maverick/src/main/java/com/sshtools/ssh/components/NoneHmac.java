package com.sshtools.ssh.components;

import com.sshtools.ssh.SshException;

public class NoneHmac implements SshHmac {

	public int getMacLength() {
		return 0;
	}

	public void generate(long sequenceNo, byte[] data, int offset, int len,
			byte[] output, int start) {
	}

	public void init(byte[] keydata) throws SshException {
	}

	public boolean verify(long sequenceNo, byte[] data, int start, int len,
			byte[] mac, int offset) {
		return true;
	}

	public void update(byte[] b) {
	}

	public byte[] doFinal() {

		return new byte[0];
	}

	public String getAlgorithm() {
		return "none";
	}

}
