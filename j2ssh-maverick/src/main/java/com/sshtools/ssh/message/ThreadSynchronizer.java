
package com.sshtools.ssh.message;

import com.sshtools.events.EventLog;

/**
 * @author Lee David Painter
 */
public class ThreadSynchronizer {


  boolean isBlocking;
  Thread blockingThread = null;
  boolean verbose = Boolean.valueOf(System.getProperty("maverick.verbose", "false")).booleanValue();
  
  public ThreadSynchronizer(boolean isBlocking) {
      this.isBlocking = isBlocking;
  }

  public boolean requestBlock(MessageStore store,
                                           MessageObserver observer,
                                           MessageHolder holder) throws
      InterruptedException {
	  
	  holder.msg = store.hasMessage(observer);

	  if(holder.msg != null) {
	       return false;
	  }
	  
	  synchronized(ThreadSynchronizer.this) {
		  
	  	// #ifdef DEBUG
		if(verbose) {
		  EventLog.LogEvent(this,"requesting block");
		}
		// #endif
	
	    boolean canBlock = !isBlocking || isBlockOwner(Thread.currentThread());
	
	    if (canBlock) {
	      isBlocking = true;
	      blockingThread = Thread.currentThread();
	    }
	    else {
	    	// #ifdef DEBUG
	    	if(verbose) {
		    	EventLog.LogEvent(this,"can't block so wait");
		    	EventLog.LogEvent(this,"isBlocking:"+isBlocking);
		    	EventLog.LogEvent(this,"blockowner name:id{"+blockingThread.getName()+"}");
		    	EventLog.LogEvent(this,"currentthread name:id{"+Thread.currentThread().getName()+"}");
	    	}
	    	// #endif
	      wait(1000);
	    }
	    return canBlock;
	  }
  }

  public synchronized boolean isBlockOwner(Thread thread) {
      return  blockingThread!=null  && blockingThread.equals(thread);
  }


  public synchronized void releaseWaiting() {
      notifyAll();
  }

  public synchronized void releaseBlock() {
    /**
     * Inform the waiting threads that they may take the connection
     */
    isBlocking = false;
    blockingThread = null;
    notifyAll();
  }

}
