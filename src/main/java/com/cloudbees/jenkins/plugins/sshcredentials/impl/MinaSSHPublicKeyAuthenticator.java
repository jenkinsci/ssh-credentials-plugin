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
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.Functions;
import hudson.util.Secret;
import org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.security.SecurityUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Does public key auth with a {@link ClientSession}.
 */
public class MinaSSHPublicKeyAuthenticator extends SSHAuthenticator<ClientSession, SSHUserPrivateKey> {

    static /*almost final*/ int authTimeout = Integer.parseInt(System.getProperty(MinaSSHPublicKeyAuthenticator.class.getName() + ".authTimeout", "15"));

    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(MinaSSHPublicKeyAuthenticator.class.getName());


    /**
     * Constructor.
     *
     * @param connection the connection we will be authenticating.
     */
    MinaSSHPublicKeyAuthenticator(@NonNull ClientSession connection,
                                         @NonNull SSHUserPrivateKey user) {
        super(connection, user, null);
    }

    /**
     * Constructor.
     *
     * @param connection the connection we will be authenticating.
     */
    MinaSSHPublicKeyAuthenticator(@NonNull ClientSession connection,
                                         @NonNull SSHUserPrivateKey user,
                                         @CheckForNull String username) {
        super(connection, user, username);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canAuthenticate() {
        return getConnection().getUserAuthFactories().stream().anyMatch(userAuthFactory -> userAuthFactory instanceof UserAuthPublicKeyFactory)
            && !getConnection().isAuthenticated() && getConnection().isOpen();
    }

    @NonNull
    @Override
    public Mode getAuthenticationMode() {
        return Mode.AFTER_CONNECT;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected boolean doAuthenticate() {
        final SSHUserPrivateKey user = getUser();
        for (String key : user.getPrivateKeys()) {
            try {
                Secret passphrase = user.getPassphrase();
                Path path = Paths.get("key");

                SecurityUtils.loadKeyPairIdentities(null,
                        new PathResource(path),
                        new ByteArrayInputStream(key.getBytes(StandardCharsets.UTF_8)),
                        passphrase == null ? null : FilePasswordProvider.of(passphrase.getPlainText()))
                    .forEach(keyPair -> getConnection().addPublicKeyIdentity(keyPair));
                getConnection().setUsername(getUsername());
                return getConnection().auth().verify(authTimeout, TimeUnit.SECONDS).isSuccess();
            } catch (IOException e) {
                Functions.printStackTrace(e, getListener().error("Could not authenticate due to I/O issue"));
            } catch (GeneralSecurityException e) {
                Functions.printStackTrace(e, getListener().error("Could not authenticate because unrecoverable key pair"));
            }
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
        @Nullable
        @Override
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
                return (SSHAuthenticator<C, U>) new MinaSSHPublicKeyAuthenticator(
                    (ClientSession) connection,
                    (SSHUserPrivateKey) user,
                    username
                );
            }
            return null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected <C, U extends StandardUsernameCredentials> boolean supports(@NonNull Class<C> connectionClass,
                                                                              @NonNull Class<U> userClass) {
            return ClientSession.class.isAssignableFrom(connectionClass)
                && SSHUserPrivateKey.class.isAssignableFrom(userClass);
        }

        private static final long serialVersionUID = 1L;
    }
}
