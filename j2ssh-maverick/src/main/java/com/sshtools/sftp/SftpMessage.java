package com.sshtools.sftp;

import java.io.IOException;

import com.sshtools.ssh.message.Message;
import com.sshtools.util.ByteArrayReader;

public
  class SftpMessage extends ByteArrayReader implements Message {

      int type;
      int requestId;

      SftpMessage(byte[] msg) throws IOException {
          super(msg);
          type = read();
          requestId = (int) readInt();
      }

      public int getType() {
          return type;
      }

      public int getMessageId() {
          return requestId;
      }

  }
