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
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.trilead.ssh2.Connection;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.util.Secret;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

/**
 * Does public key auth with a {@link Connection}.
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
        this(connection, user, null);
    }

    /**
     * Constructor.
     *
     * @param connection the connection we will be authenticating.
     */
    public TrileadSSHPublicKeyAuthenticator(@NonNull Connection connection,
                                            @NonNull SSHUserPrivateKey user,
                                            @CheckForNull String username) {
        super(connection, user, username);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canAuthenticate() {
        try {
            return getRemainingAuthMethods().contains("publickey");
        } catch (IOException e) {
            e.printStackTrace(getListener().error("Failed to authenticate"));
            return false;
        }
    }

    private List<String> getRemainingAuthMethods() throws IOException {
        return Arrays.asList(getConnection().getRemainingAuthMethods(getUsername()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected boolean doAuthenticate() {
        final SSHUserPrivateKey user = getUser();
        final String username = getUsername();
        try {
            final Connection connection = getConnection();
            final Secret userPassphrase = user.getPassphrase();
            final String passphrase = userPassphrase == null ? null : userPassphrase.getPlainText();

            Collection<String> availableMethods = getRemainingAuthMethods();
            if (availableMethods.contains("publickey")) {
                int count = 0;
                List<IOException> ioe = new ArrayList<IOException>();
                for (String privateKey : getPrivateKeys(user)) {
                    try {
                        if (connection.authenticateWithPublicKey(username, privateKey.toCharArray(), passphrase)) {
                            LOGGER.fine("Authentication with 'publickey' succeeded.");
                            return true;
                        }
                    } catch (IOException e) {
                        ioe.add(e);
                    }
                    count++;
                    getListener()
                            .error("Server rejected the %d private key(s) for %s (credentialId:%s/method:publickey)",
                                    count, username, user.getId());
                }
                for (IOException e : ioe) {
                    e.printStackTrace(getListener()
                            .error("Failed to authenticate as %s with credential=%s", username, getUser().getId()));
                }
                return false;
            } else {
                getListener().error("The server does not allow public key authentication. Available options are %s",
                        availableMethods);
                return false;
            }
        } catch (IOException e) {
            e.printStackTrace(getListener()
                    .error("Failed to authenticate as %s with credential=%s", username, getUser().getId()));
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
        protected <C, U extends StandardUsernameCredentials> SSHAuthenticator<C, U> newInstance(@NonNull C connection,
                                                                                                @NonNull U user) {
            return newInstance(connection, user, null);
        }

        /**
         * {@inheritDoc}
         */
        @Nullable
        @Override
        @SuppressWarnings("unchecked")
        protected <C, U extends StandardUsernameCredentials> SSHAuthenticator<C, U> newInstance(@NonNull C connection,
                                                                                                @NonNull U user,
                                                                                                @CheckForNull String
                                                                                                        username) {
            if (supports(connection.getClass(), user.getClass())) {
                return (SSHAuthenticator<C, U>) new TrileadSSHPublicKeyAuthenticator((Connection) connection,
                        (SSHUserPrivateKey) user, username);
            }
            return null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected <C, U extends StandardUsernameCredentials> boolean supports(@NonNull Class<C> connectionClass,
                                                                              @NonNull Class<U> userClass) {
            return Connection.class.isAssignableFrom(connectionClass)
                    && SSHUserPrivateKey.class.isAssignableFrom(userClass);
        }

        private static final long serialVersionUID = 1L;
    }
}
