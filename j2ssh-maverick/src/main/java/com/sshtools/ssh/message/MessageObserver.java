package com.sshtools.ssh.message;

public interface MessageObserver {

    public boolean wantsNotification(Message msg);
}
