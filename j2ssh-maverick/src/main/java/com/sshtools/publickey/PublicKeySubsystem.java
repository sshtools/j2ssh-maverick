
package com.sshtools.publickey;

import java.io.IOException;
import java.util.Vector;

import com.sshtools.ssh.Packet;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SubsystemChannel;
import com.sshtools.ssh.components.SshPublicKey;
import com.sshtools.ssh2.Ssh2Session;
import com.sshtools.util.ByteArrayReader;


/**
 * This class implements version 1 of the public key subsystem.
 *
 * @author Lee David Painter
 */
public class PublicKeySubsystem
   extends SubsystemChannel {

  static final int SSH_PUBLICKEY_SUCCESS = 0;
  static final int SSH_PUBLICKEY_ACCESS_DENIED = 1;
  static final int SSH_PUBLICKEY_STORAGE_EXCEEDED = 2;
  static final int SSH_PUBLICKEY_VERSION_NOT_SUPPORTED = 3;
  static final int SSH_PUBLICKEY_KEY_NOT_FOUND = 4;
  static final int SSH_PUBLICKEY_KEY_NOT_SUPPORTED = 5;
  static final int SSH_PUBLICKEY_KEY_ALREADY_PRESENT = 6;
  static final int SSH_PUBLICKEY_GENERAL_FAILURE = 7;
  static final int SSH_PUBLICKEY_REQUEST_NOT_SUPPORTED = 8;

  static final int VERSION_1 = 1;
  static final int VERSION_2 = 2;

  int version;

  public PublicKeySubsystem(Ssh2Session session)
     throws SshException {
    super(session);

    try {
      if(!session.startSubsystem("publickey@vandyke.com")) {
        throw new SshException(
           "The remote side failed to start the publickey subsystem",
           SshException.CHANNEL_FAILURE);
      }

      Packet msg = createPacket();
      msg.writeString("version");
      msg.writeInt(VERSION_1);

      sendMessage(msg);

      ByteArrayReader response = new ByteArrayReader(nextMessage());

      //String v = 
      response.readString();

      int serverVersion = (int)response.readInt();
      version = Math.min(serverVersion, VERSION_1);

    }
    catch(IOException ex) {
      throw new SshException(SshException.INTERNAL_ERROR, ex);
    }

  }

  /**
   * Add a public key to the users list of acceptable keys.
   *
   * @param key
   * @param comment
   * @throws SshException
   * @throws PublicKeyStatusException
   */
  public void add(SshPublicKey key, String comment)
     throws
     SshException, PublicKeySubsystemException {

    try {
      Packet msg = createPacket();
      msg.writeString("add");
      msg.writeString(comment);
      msg.writeString(key.getAlgorithm());
      msg.writeBinaryString(key.getEncoded());

      sendMessage(msg);

      readStatusResponse();

    }
    catch(IOException ex) {
      throw new SshException(ex);
    }

  }

  /**
   * Remove a public key from the users list of acceptable keys.
   * @param key
   * @throws SshException
   * @throws PublicKeyStatusException
   */
  public void remove(SshPublicKey key)
     throws SshException,
     PublicKeySubsystemException {

    try {

      Packet msg = createPacket();
      msg.writeString("remove");
      msg.writeString(key.getAlgorithm());
      msg.writeBinaryString(key.getEncoded());

      sendMessage(msg);

      readStatusResponse();

    }
    catch(IOException ex) {
      throw new SshException(ex);
    }
  }

  /**
   * List all of the users acceptable keys.
   * @return SshPublicKey[]
   */
  public SshPublicKey[] list()
     throws SshException, PublicKeySubsystemException {

    try {

      Packet msg = createPacket();
      msg.writeString("list");

      sendMessage(msg);

      Vector<SshPublicKey> keys = new Vector<SshPublicKey>();

      while(true) {
        ByteArrayReader response = new ByteArrayReader(nextMessage());

        String type = response.readString();

        if(type.equals("publickey")) {
          @SuppressWarnings("unused")
          String comment = 
        	  response.readString();
          String algorithm = 
        	  response.readString();
          keys.addElement(
             SshPublicKeyFileFactory.decodeSSH2PublicKey(algorithm, 
             response.readBinaryString()));

        }
        else if(type.equals("status")) {
          int status = (int)response.readInt();
          String desc = response.readString();

          if(status != PublicKeySubsystemException.SUCCESS) {
            throw new PublicKeySubsystemException(status, desc);
          }
		SshPublicKey[] array = new SshPublicKey[keys.size()];
		keys.copyInto(array);

		return array;

        }
        else {
          throw new SshException(
             "The server sent an invalid response to a list command",
             SshException.PROTOCOL_VIOLATION);
        }
      }
    }
    catch(IOException ex) {
      throw new SshException(ex);
    }

  }

  /**
   * Associate a command with an accepted public key. The request will fail
   * if the public key is not currently in the users acceptable list. Also
   * some server implementations may choose not to support this feature.
   * @param key
   * @param command
   * @throws SshException
   * @throws PublicKeyStatusException
   */
  public void associateCommand(SshPublicKey key, String command)
     throws
     SshException, PublicKeySubsystemException {

    try {

      Packet msg = createPacket();
      msg.writeString("command");
      msg.writeString(key.getAlgorithm());
      msg.writeBinaryString(key.getEncoded());
      msg.writeString(command);

      sendMessage(msg);

      readStatusResponse();

    }
    catch(IOException ex) {
      throw new SshException(ex);
    }

  }

  /**
   * Read a status response and throw an exception if an error has occurred.
   *
   * @throws SshException
   * @throws PublicKeyStatusException
   */
  void readStatusResponse()
     throws SshException, PublicKeySubsystemException {

    try {
      ByteArrayReader msg = new ByteArrayReader(nextMessage());

//      String str = 
    	  msg.readString();
      int status = (int)msg.readInt();
      String desc = msg.readString();

      if(status != PublicKeySubsystemException.SUCCESS) {
        throw new PublicKeySubsystemException(status, desc);
      }
    }
    catch(IOException ex) {
      throw new SshException(ex);
    }
  }

}
