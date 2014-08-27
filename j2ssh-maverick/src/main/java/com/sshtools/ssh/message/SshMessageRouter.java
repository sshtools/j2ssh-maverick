
package com.sshtools.ssh.message;

import java.io.IOException;
import java.util.Vector;

import com.sshtools.events.EventLog;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshIOException;

/**
 * <p>This abstract class provides a synchronized message routing framework. The protocol implementation supplies a message
 * reader interface, to which only one thread is allowed access at any one time, threads requiring a message
 * whilst another thread is blocking are queued to await notification of when the reader is available. Since
 * a message read by one thread may be destined for another the router takes charge of this before notifying
 * other queued threads that the block is available. When they receive this notification they first check their own
 * message stores before requesting the block again.<p>
 *
 * @author Lee David Painter
 */
public abstract class SshMessageRouter {

  private SshAbstractChannel[] channels;
  SshMessageReader reader;
  SshMessageStore global;
  ThreadSynchronizer sync;
  private int count = 0;
  boolean buffered;
  MessagePump messagePump;
  boolean isClosing = false; 
  Vector activeChannels = new Vector();
  Vector shutdownHooks = new Vector();
  boolean verbose = Boolean.valueOf(System.getProperty("maverick.verbose", "false")).booleanValue();
  
  public SshMessageRouter(SshMessageReader reader, int maxChannels, boolean buffered) {
    this.reader = reader;
    this.buffered = buffered;
    this.channels = new SshAbstractChannel[maxChannels];
    this.global = new SshMessageStore(this, null, new MessageObserver() {
     public boolean wantsNotification(Message msg) {
         return false;
     }
    });

    sync = new ThreadSynchronizer(buffered);

    if(buffered) {
        messagePump = new MessagePump();
        sync.blockingThread = messagePump;
        // J2SE messagePump.setDaemon(true);
    }

  }

  public void start() {
	    // #ifdef DEBUG
	  	if(verbose) {
	  		EventLog.LogEvent(this,"starting message pump");
	  	}
		// #endif
      if(messagePump!=null && !messagePump.isRunning()) {
    	  	String prefix="";
    	  	String sourceThread=Thread.currentThread().getName();
			if(sourceThread.indexOf('-')>-1) {
				prefix=sourceThread.substring(0,1+sourceThread.indexOf('-'));
				// retrieve an event Listener
				// pass the event to the listener to process
			}
			messagePump.setName(prefix+"MessagePump_"+messagePump.getName());
			messagePump.start();
			// #ifdef DEBUG
			if(verbose) {
				EventLog.LogEvent(this,"message pump started thread name:"+messagePump.getName());
			}
			// #endif
      }
  }
  
  public void addShutdownHook(Runnable r) {
      if(r!=null)
          shutdownHooks.addElement(r);
  }

  public boolean isBuffered() {
      return buffered;
  }

  public void stop() {

      signalClosingState();

      if(messagePump!=null)
          messagePump.stopThread();
      
      if(shutdownHooks!=null) {
	      for(int i=0;i<shutdownHooks.size();i++) {
		       try {
		           ((Runnable) shutdownHooks.elementAt(i)).run();
		       } catch (Throwable t) {
		       }
		  }
      }
  }

  public void signalClosingState() {
      if(buffered && messagePump!=null) {
          synchronized(messagePump) {
              isClosing = true;
          }
      }
  }

  protected SshMessageStore getGlobalMessages() {
    return global;
  }
  
  public int getMaxChannels() {
	  return channels.length;
  }

  protected int allocateChannel(SshAbstractChannel channel) {

    synchronized (channels) {
      for (int i = 0; i < channels.length; i++) {
        if (channels[i] == null) {
          channels[i] = channel;
		  activeChannels.addElement(channel);  
          count++;
          // #ifdef DEBUG
          EventLog.LogEvent(this, "Allocated channel " + i);
          // #endif
          return i;
        }
      }
      return -1;
    }
  }

	protected void freeChannel(SshAbstractChannel channel) {
		synchronized (channels) {
			
			if(channels[channel.getChannelId()]!=null) {
				if(channel.equals(channels[channel.getChannelId()])) {
					channels[channel.getChannelId()] = null;
					activeChannels.removeElement(channel);
					count--;
					 // #ifdef DEBUG
					EventLog.LogEvent(this, "Freed channel " + channel.getChannelId());
					 // #endif
				}
			}
		}
	}
	
	protected SshAbstractChannel[] getActiveChannels() {
		return (SshAbstractChannel[]) activeChannels.toArray(new SshAbstractChannel[0]);
	}

  protected int maximumChannels() {
    return channels.length;
  }

  public int getChannelCount() {
    return count;
  }

  protected SshMessage nextMessage(SshAbstractChannel channel, MessageObserver observer, long timeout) throws
      SshException, InterruptedException {

    long startTime = System.currentTimeMillis();
    
    SshMessageStore store = channel == null ? global : channel.getMessageStore();
	// #ifdef DEBUG
	if(verbose) {
		EventLog.LogEvent(this,"using "+(channel == null ? "global store":"channel store"));
	}
	// #endif
    MessageHolder holder = new MessageHolder();

    while (holder.msg == null 
    		&& (timeout==0 || System.currentTimeMillis()-startTime < timeout)) {
       /**
        * There are no messages for this caller. First check the buffered
        * state and look for possible errors from the buffer thread
        */
       if(buffered && messagePump!=null) {
	    	// #ifdef DEBUG
	   		if(verbose) {
	   			EventLog.LogEvent(this,"waiting for messagePump lock");
	   		}
	   		// #endif
           synchronized(messagePump) {
               if(!isClosing) {
                   if (messagePump.lastError != null) {
                	   Throwable tmpEx = messagePump.lastError;
                	   messagePump.lastError = null;
                	   if (tmpEx instanceof SshException) {
                    	// #ifdef DEBUG
                       	EventLog.LogEvent(this,"messagePump has SshException this will be caught by customer code");
                       	// #endif
                    	   throw (SshException) tmpEx;
                       }
                       else if (tmpEx instanceof SshIOException) {
                    	   // #ifdef DEBUG
                    	   EventLog.LogEvent(this,"messagePump has SshIOException this will be caught by customer code");
                    	   // #endif
                           throw ((SshIOException) tmpEx).getRealException();
                       }
                       else {
                    	   // #ifdef DEBUG
                    	   EventLog.LogEvent(this,"messagePump has some other exception this will be caught by customer code");
                    	   // #endif
                           throw new SshException(tmpEx);
                       }
                   }
               }
           }
       }


       /**
        * Request a block on the message reader
        */
       if (sync.requestBlock(store, observer, holder)) {

           try {
        		// #ifdef DEBUG
        		if(verbose) {
        			EventLog.LogEvent(this,"block for message");
        		}
        		// #endif
               blockForMessage();

           } finally {
               // Release the block so that other threads may block or return with the
               // newly arrived message
               sync.releaseBlock();
           }
       }
    }

    if(holder.msg==null) {
    	// #ifdef DEBUG
    	EventLog.LogDebugEvent(this, "Mesage timeout reached timeout=" + timeout);
    	// #endif
    	throw new SshException( 
    			"The message was not received before the specified timeout period timeout=" + timeout,
    			SshException.MESSAGE_TIMEOUT);
    }
    
    return (SshMessage) holder.msg;
  }

  public boolean isBlockingThread(Thread thread) {
      return sync.isBlockOwner(thread);
  }


  private void blockForMessage()
          throws SshException {

      // Read and create a message
      SshMessage message = createMessage(reader.nextMessage());
	  	// #ifdef DEBUG
	  if(verbose) {	
		  EventLog.LogEvent(this,"read next message");
	  }
	  	// #endif
      // Determine the destination channel (if any)
      SshAbstractChannel destination = null;
      if (message instanceof SshChannelMessage) {
          destination = channels[((SshChannelMessage) message).getChannelId()];
      }

      // Call the destination so that they may process the message
      boolean processed = destination == null ?
                          processGlobalMessage(message)
                          :
                          destination.processChannelMessage((SshChannelMessage) message);

      // If the previous call did not process the message then add to the
      // destinations message store
      if (!processed) {
          SshMessageStore ms = destination == null ?
                               global
                               : destination.getMessageStore();
          //add new message to message stores linked list.
          ms.addMessage(message);
      }
  }
  
  
  /**
   * Called when the threaded router closes.
   */
  protected abstract void onThreadExit();

  /**
   * <p>Called by the message routing framework to request the creation of an
   * {@link SshMessage}.</p>
   *
   * @param messageid
   * @return the new message instance
   */
  protected abstract SshMessage createMessage(byte[] msg) throws SshException;

  /**
   * <p>Called by the message routing framework so that the routing implementation may process
   * a global message. If the message is processed and no further action is required this method
   * should return <code>true</code>, if the method returns <code>false</code> then the message
   * will be added to the global message store.</p>
   *
   * @param msg
   * @return <code>true</code> if the message was processed, otherwise <code>false</code>
   * @throws IOException
   */
  protected abstract boolean processGlobalMessage(SshMessage msg) throws
      SshException;



   class MessagePump extends Thread {

       Throwable lastError;
       boolean running = false;

       public void run() {

    	   try {
	           running = true;
	
	           while(running) {
	
	               try {
	                   blockForMessage();
	
	                   // We have a message so release waiting threads
	                   sync.releaseWaiting();
	
	               } catch(Throwable t) {
	
	                   synchronized(MessagePump.this) {
	                       // If were not closing then save this error
	                       if(!isClosing) {
	                    	   EventLog.LogEvent(this,"Message pump caught exception: " + t.getMessage());
	                           lastError = t;
	                       }
	                       stopThread();
	                   }
	               }
	           }
	
	           // Finally release the block as we exit
	           sync.releaseBlock();

    	   } finally {
    		   onThreadExit();
    	   }
       }

       public void stopThread() {
           running = false;
           if(!Thread.currentThread().equals(this))
               interrupt();
       }

       public boolean isRunning() {
           return running;
       }
   }

}
