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
import com.trilead.ssh2.Connection;
import com.trilead.ssh2.InteractiveCallback;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.logging.Logger;

/**
 * Does password auth with a {@link Connection}.
 */
public class TrileadSSHPasswordAuthenticator extends SSHAuthenticator<Connection, SSHUserPassword> {

    /**
     * Our logger
     */
    private static final Logger LOGGER = Logger.getLogger(TrileadSSHPasswordAuthenticator.class.getName());

    /**
     * Constructor.
     *
     * @param connection the connection we will be authenticating.
     */
    public TrileadSSHPasswordAuthenticator(Connection connection, SSHUserPassword user) {
        super(connection, user);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canAuthenticate() {
        try {
            for (String authMethod : getConnection().getRemainingAuthMethods(getUser().getUsername())) {
                if ("password".equals(authMethod)) {
                    // prefer password
                    return true;
                }
                if ("keyboard-interactive".equals(authMethod)) {
                    return true;
                }
            }
        } catch (IOException e) {
            e.printStackTrace(getListener().error("Failed to authenticate"));
        }
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected boolean doAuthenticate() {
        final SSHUserPassword user = getUser();
        final String username = user.getUsername();

        try {
            final Connection connection = getConnection();
            final String password = user.getPassword().getPlainText();
            boolean tried = false;

            List<String> availableMethods = Arrays.asList(connection.getRemainingAuthMethods(username));
            if (availableMethods.contains("password")) {
                // prefer password
                if (connection.authenticateWithPassword(username, password)) {
                    LOGGER.fine("Authentication with 'password' succeeded.");
                    return true;
                }
                getListener().error("Failed to authenticate as %s. Wrong password. (credentialId:%s/method:password)", username, user.getId());
                tried = true;
            }
            if (availableMethods.contains("keyboard-interactive")) {
                if (connection.authenticateWithKeyboardInteractive(username, new InteractiveCallback() {
                    public String[] replyToChallenge(String name, String instruction, int numPrompts,
                                                     String[] prompt, boolean[] echo)
                            throws Exception {
                        // most SSH servers just use keyboard interactive to prompt for the password
                        // match "assword" is safer than "password"... you don't *want* to know why!
                        return prompt != null && prompt.length > 0 && prompt[0].toLowerCase(Locale.ENGLISH).contains("assword")
                                ? new String[]{password}
                                : new String[0];
                    }
                })) {
                    LOGGER.fine("Authentication with  'keyboard-interactive' succeeded.");
                    return true;
                }
                getListener().error("Failed to authenticate as %s. Wrong password. (credentialId:%s/method:keyboard-interactive)", username, user.getId());
                tried = true;
            }

            if (!tried) {
                getListener().error("The server does not allow password authentication. Available options are %s",availableMethods);
            }
        } catch (IOException e) {
            e.printStackTrace(getListener().error("Unexpected error while trying to authenticate as %s with credential=%s",username,user.getId()));
        }
        return false;
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
                return (SSHAuthenticator<C, U>) new TrileadSSHPasswordAuthenticator((Connection) connection,
                        (SSHUserPassword) user);
            }
            return null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected <C, U extends SSHUser> boolean supports(@NonNull Class<C> connectionClass,
                                                          @NonNull Class<U> userClass) {
            return Connection.class.isAssignableFrom(connectionClass) && SSHUserPassword.class
                    .isAssignableFrom(userClass);
        }
    }
}
