package com.sshtools.events;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

/**
 * Event Service Implementation singleton, that manages J2SSH Event Listeners,
 * and allows events to be fired.
 * 
 * @author david
 */
public class EventServiceImplementation implements EventService {
    /** Singleton */
    private static final EventService INSTANCE = new EventServiceImplementation();
    private final Hashtable<String,EventListener> keyedListeners;
    private Vector<EventListener> globalListeners = new Vector<EventListener>();

    protected EventServiceImplementation() {
        keyedListeners = new Hashtable<String,EventListener>();
    }

    /**
     * Get the event service instance
     * 
     * @return EventService
     */
    public static EventService getInstance() {
        return INSTANCE;
    }

    /**
     * Add a J2SSH Listener to the list of listeners that will be sent events
     * @param threadPrefix listen to threads whose name have this prefix, string must not contain any '-' except the final character which must be a '-'.  
     * @param listener
     */
    public synchronized void addListener(String threadPrefix, EventListener listener) {
    	if(threadPrefix.trim().equals("")) {
    		globalListeners.addElement(listener);
    	} else {
    		keyedListeners.put(threadPrefix.trim(), listener);
    	}
    }

    /**
     * Remove an EventListener from the list of listeners that are sent events
     */
    public synchronized void removeListener(String threadPrefix) {
        keyedListeners.remove(threadPrefix);
    }

    /**
     * Send an SSH Event to each registered listener
     */
    public synchronized void fireEvent(Event evt) {
        if (evt == null) {
            return;
        }
        
        // Process global listeners
        for(Enumeration<EventListener> keys = globalListeners.elements(); keys.hasMoreElements();) {
        	EventListener mListener = keys.nextElement();
        	try {
        		mListener.processEvent(evt);
        	} catch(Throwable t) { }
        }

        String sourceThread = Thread.currentThread().getName();
        
        for (Enumeration<String> keys = keyedListeners.keys(); keys.hasMoreElements();) {
        	String key = (String) keys.nextElement();
            // We don't want badly behaved listeners to throw uncaught
            // exceptions and upset other listeners
            try {
            	String prefix="";
            	if(sourceThread.indexOf('-')>-1) {
            		prefix=sourceThread.substring(0,sourceThread.indexOf('-'));

                	if(key.startsWith(prefix)) {
                		EventListener mListener = keyedListeners.get(key);
                		mListener.processEvent(evt);
                	}
            	}
            	

            } catch (Throwable thr) {
                // log.error("Event failed.", thr);
            }
        }
    }

	public void addListener(EventListener listener) {
		addListener("", listener);
	}
}