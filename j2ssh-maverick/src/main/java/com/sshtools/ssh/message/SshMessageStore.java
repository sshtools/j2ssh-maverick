
package com.sshtools.ssh.message;

import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;

import com.sshtools.events.EventLog;
import com.sshtools.ssh.SshException;

/**
 * <p>This class is the central storage location for channel messages; each channel
 * has its own message store and the message pump delivers them here where they
 * are stored in a lightweight linked list.</p>
 *
 * @author Lee David Painter
 */
public class SshMessageStore implements MessageStore {

  public static final int NO_MESSAGES = -1;
  SshAbstractChannel channel;
  SshMessageRouter manager;
  boolean closed = false;
  SshMessage header = new SshMessage();
  int size = 0;
  MessageObserver stickyMessageObserver;
  boolean verbose = Boolean.valueOf(System.getProperty("maverick.verbose", "false")).booleanValue();
  
  public SshMessageStore(SshMessageRouter manager,
                         SshAbstractChannel channel,
                         MessageObserver stickyMessageObserver) {
    this.manager = manager;
    this.channel = channel;
    this.stickyMessageObserver = stickyMessageObserver;
    header.next = header.previous = header;
  }

  /**
   *
   * @param messagefilter
   * @param timeout
   * @return SshMessage
   * @throws IOException
   * @throws InterruptedIOException
   */
  public SshMessage nextMessage(MessageObserver observer, long timeout) throws SshException,
      EOFException {

    try {
		SshMessage msg = manager.nextMessage(channel, observer, timeout);
		// #ifdef DEBUG
		if(verbose) {
			EventLog.LogEvent(this,"got managers next message");
		}
		// #endif

		if (msg != null) {
		    synchronized (header) {
		
		      if(stickyMessageObserver.wantsNotification(msg)) {
		          return msg;
		      }
		
		      remove(msg);
		      return msg;
		    }
		}
    }
    catch (InterruptedException ex) {
      throw new SshException("The thread was interrupted",
                             SshException.INTERNAL_ERROR);
    }

    throw new EOFException("The required message could not be found in the message store");
  }

  public boolean isClosed() {
    synchronized (header) {
      return closed;
    }
  }

  private void remove(SshMessage e) {


      if (e == header) {
      throw new IndexOutOfBoundsException();
    }

    e.previous.next = e.next;
    e.next.previous = e.previous;
    size--;
  }

  public Message hasMessage(MessageObserver observer) {
  		// #ifdef DEBUG
 		if(verbose) {
 			EventLog.LogEvent(this,"waiting for header lock");
 		}
 		// #endif

    synchronized (header) {

    	//this would not seem to take account of header being null, or header.next.next being null, perhaps because these states are not possible? if so document, if not fix.
     SshMessage e = header.next;
      if (e == null) {
    	// #ifdef DEBUG
  		if(verbose) {
    	  EventLog.LogEvent(this,"header.next is null");
  		}
  		// #endif
        return null;
      }

      //cycle through the linked list until we reach the start point (header), 
      //checking to see if the message is of a type that the observer is interested in.
      //??don't seem to look at header though!??
      for (; e != header; e = e.next) {
        if(observer.wantsNotification(e)) {
        	// #ifdef DEBUG
     		if(verbose) {
     			EventLog.LogEvent(this,"found message");
     		}
     		// #endif
        	return e;
        }
      }

  		// #ifdef DEBUG
		if(verbose) {
			EventLog.LogEvent(this,"no messages");
		}
		// #endif
      return null;

    }
  }



  public void close() {

    synchronized (header) {
      closed = true;
    }
  }

  void addMessage(SshMessage msg) {
      synchronized(header) {
    	  //insert this message between header and header.previous, and change their links appropriately
    	  msg.next = header;
          msg.previous = header.previous;
          //change message before header
          msg.previous.next = msg;
          //change header
          msg.next.previous = msg;
          size++;
      }
  }
}
