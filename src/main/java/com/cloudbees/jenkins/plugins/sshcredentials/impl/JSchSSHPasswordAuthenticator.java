package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticator;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticatorFactory;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UIKeyboardInteractive;
import com.jcraft.jsch.UserInfo;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;

import java.util.logging.Logger;

/**
 * @author stephenc
 * @since 25/10/2012 13:57
 */
public class JSchSSHPasswordAuthenticator extends SSHAuthenticator<JSchConnector, StandardUsernamePasswordCredentials> {

    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(JSchSSHPasswordAuthenticator.class.getName());

    protected JSchSSHPasswordAuthenticator(@NonNull JSchConnector connection,
                                           @NonNull StandardUsernamePasswordCredentials user) {
        super(connection, user);
    }

    @NonNull
    @Override
    public Mode getAuthenticationMode() {
        return Mode.BEFORE_CONNECT;
    }

    @Override
    public boolean canAuthenticate() {
        return !getConnection().hasSession()
                || (getConnection().getSession().isConnected() && getConnection().getSession().getUserInfo() == null);
    }

    @Override
    protected boolean doAuthenticate() {
        final Session session = getConnection().getSession();
        session.setUserInfo(new JSchUserInfo());
        session.setPassword(getUser().getPassword().getPlainText());
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Extension(optional = true)
    public static class Factory extends SSHAuthenticatorFactory {

        /**
         * {@inheritDoc}
         */
        @Override
        @SuppressWarnings("unchecked")
        protected <C, U extends StandardUsernameCredentials> SSHAuthenticator<C, U> newInstance(@NonNull C connection,
                                                                                                @NonNull U user) {
            if (supports(connection.getClass(), user.getClass())) {
                return (SSHAuthenticator<C, U>) new JSchSSHPasswordAuthenticator((JSchConnector) connection,
                        (StandardUsernamePasswordCredentials) user);
            }
            return null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected <C, U extends StandardUsernameCredentials> boolean supports(@NonNull Class<C> connectionClass,
                                                                              @NonNull Class<U> userClass) {
            return JSchConnector.class.isAssignableFrom(connectionClass)
                    && StandardUsernamePasswordCredentials.class.isAssignableFrom(userClass);
        }

        private static final long serialVersionUID = 1L;
    }

    private class JSchUserInfo implements UserInfo, UIKeyboardInteractive {

        public String getPassphrase() {
            return "";
        }

        public String getPassword() {
            return getUser().getPassword().getPlainText();
        }

        public boolean promptPassword(String message) {
            LOGGER.info(message);
            return true;
        }

        public boolean promptPassphrase(String message) {
            LOGGER.info(message);
            return false;
        }

        public boolean promptYesNo(String message) {
            LOGGER.info(message);
            return false;
        }

        public void showMessage(String message) {
            LOGGER.info(message);
        }

        public String[] promptKeyboardInteractive(String destination, String name, String instruction, String[] prompt,
                                                  boolean[] echo) {
            // most SSH servers just use keyboard interactive to prompt for the password
            // match "assword" is safer than "password"... you don't *want* to know why!
            return prompt != null && prompt.length > 0 && prompt[0].toLowerCase().contains("assword")
                    ? new String[]{getUser().getPassword().getPlainText()}
                    : new String[0];
        }
    }
}
