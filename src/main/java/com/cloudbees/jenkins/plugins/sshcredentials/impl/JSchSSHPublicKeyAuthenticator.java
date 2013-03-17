package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticator;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticatorException;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticatorFactory;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUser;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.jcraft.jsch.JSchException;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;

import java.io.UnsupportedEncodingException;
import java.util.logging.Logger;

/**
 * @author stephenc
 * @since 25/10/2012 14:49
 */
public class JSchSSHPublicKeyAuthenticator extends SSHAuthenticator<JSchConnector, SSHUserPrivateKey> {

    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(TrileadSSHPublicKeyAuthenticator.class.getName());

    /**
     * Constructor.
     *
     * @param connector the connection we will be authenticating.
     */
    public JSchSSHPublicKeyAuthenticator(JSchConnector connector, SSHUserPrivateKey user) {
        super(connector, user);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canAuthenticate() {
        return !getConnection().hasSession()
                || (getConnection().getSession().isConnected() && getConnection().getSession().getUserInfo() == null);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected boolean doAuthenticate() {
        try {
            final SSHUserPrivateKey user = getUser();
            final Secret userPassphrase = user.getPassphrase();
            final String passphrase = userPassphrase == null ? null : userPassphrase.getPlainText();
            getConnection().getJSch().addIdentity(user.getUsername(), user.getPrivateKey().getBytes("UTF-8"), null,
                    passphrase == null ? null : passphrase.getBytes("UTF-8"));

            return true;
        } catch (JSchException e) {
            LOGGER.warning(e.getMessage());
            return true;
        } catch (UnsupportedEncodingException e) {
            throw new SSHAuthenticatorException(e);
        }
    }

    @NonNull
    @Override
    public Mode getAuthenticationMode() {
        return Mode.BEFORE_CONNECT;
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
        protected <C, U extends SSHUser> SSHAuthenticator<C, U> newInstance(@NonNull C session, @NonNull U user) {
            if (supports(session.getClass(), user.getClass())) {
                return (SSHAuthenticator<C, U>) new JSchSSHPublicKeyAuthenticator((JSchConnector) session,
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
            return JSchConnector.class.isAssignableFrom(connectionClass)
                    && SSHUserPrivateKey.class.isAssignableFrom(userClass);
        }
    }
}