/*
 * The MIT License
 *
 * Copyright (c) 2011-2012, CloudBees, Inc., Stephen Connolly.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticator;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticatorFactory;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUser;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPassword;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.trilead.ssh2.Connection;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

/**
 *  Does public key auth with a {@link Connection}.
 */
public class TrileadSSHPublicKeyAuthenticator extends SSHAuthenticator<Connection, SSHUserPrivateKey> {

    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(TrileadSSHPublicKeyAuthenticator.class.getName());

    /**
     * Constructor.
     *
     * @param connection the connection we will be authenticating.
     */
    public TrileadSSHPublicKeyAuthenticator(Connection connection, SSHUserPrivateKey user) {
        super(connection, user);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canAuthenticate() {
        try {
            for (String authMethod : getConnection().getRemainingAuthMethods(getUser().getUsername())) {
                if ("publickey".equals(authMethod)) {
                    // prefer password
                    return true;
                }
            }
        } catch (IOException e) {
            // ignore, connection is in a state where we cannot authenticate.
        }
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected boolean doAuthenticate() {
        try {
            final Connection connection = getConnection();
            final SSHUserPrivateKey user = getUser();
            final String username = user.getUsername();
            final char[] key = user.getPrivateKey().toCharArray();
            final Secret userPassphrase = user.getPassphrase();
            final String passphrase = userPassphrase == null ? null : userPassphrase.getPlainText();
            while (true) {
                Set<String> availableMethods =
                        new HashSet<String>(Arrays.asList(connection.getRemainingAuthMethods(username)));
                if (availableMethods.contains("publickey")) {
                    if (connection.authenticateWithPublicKey(username, key, passphrase)) {
                        LOGGER.info("Authentication with 'publickey' succeeded.");
                        return true;
                    }
                    LOGGER.info("Authentication with 'publickey' failed.");
                } else {
                    return false;
                }
            }
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Extension
    public static class Factory extends SSHAuthenticatorFactory {

        /**
         * {@inheritDoc}
         */
        @Override
        @SuppressWarnings("unchecked")
        protected <C, U extends SSHUser> SSHAuthenticator<C, U> newInstance(@NonNull C connection, @NonNull U user) {
            if (supports(connection.getClass(), user.getClass())) {
                return (SSHAuthenticator<C, U>) new TrileadSSHPublicKeyAuthenticator((Connection) connection,
                        (SSHUserPrivateKey) user);
            }
            return null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected <C, U extends SSHUser> boolean supports(@NonNull Class<C> connectionClass,
                                                          @NonNull Class<U> userClass) {
            return Connection.class.isAssignableFrom(connectionClass)
                    && SSHUserPrivateKey.class.isAssignableFrom(userClass);
        }
    }
}
