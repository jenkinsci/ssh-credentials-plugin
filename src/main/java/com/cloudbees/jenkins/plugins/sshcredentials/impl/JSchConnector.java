package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticatorException;import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

/**
 * @author stephenc
 * @since 25/10/2012 15:14
 */
public class JSchConnector {
    private final JSch jsch;
    private final String host;
    private final int port;
    private Session session = null;
    private final String username;

    public JSchConnector(String username, String host, int port) {
        this(new JSch(), username, host, port);
    }

    public JSchConnector(JSch jsch, String username, String host, int port) {
        this.host = host;
        this.jsch = jsch;
        this.port = port;
        this.username = username;
    }

    public JSch getJSch() {
        return jsch;
    }

    public synchronized boolean hasSession() {
        return session != null;
    }

    public synchronized Session getSession() {
        if (!hasSession()) {
            try {
                session = jsch.getSession(username, host, port);
            } catch (JSchException e) {
                throw new SSHAuthenticatorException(e);
            }
        }
        return session;
    }

    public synchronized void close() {
        if (session != null) {
            session.disconnect();
            session = null;
        }
    }
}
