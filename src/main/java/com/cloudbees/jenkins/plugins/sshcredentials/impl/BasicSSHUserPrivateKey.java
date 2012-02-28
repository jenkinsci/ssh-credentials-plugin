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

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.BaseCredentials;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.FilePath;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.remoting.VirtualChannel;
import hudson.util.Secret;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.putty.PuTTYKey;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.io.StringReader;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A simple username / password for use with SSH connections.
 */
public class BasicSSHUserPrivateKey extends BaseCredentials implements SSHUserPrivateKey {

    /**
     * The description.
     */
    private final String description;

    /**
     * The username.
     */
    private final String username;

    /**
     * The password.
     */
    private final Secret passphrase;

    /**
     * The private key. If you care about securing this, use a passphrase.
     */
    private final PrivateKeySource privateKeySource;

    /**
     * The private key.
     */
    private transient volatile String privateKey;

    /**
     * Constructor for stapler.
     *
     * @param scope            the credentials scope
     * @param username         the username.
     * @param passphrase       the password.
     * @param description      the description.
     * @param privateKeySource the private key.
     */
    @DataBoundConstructor
    public BasicSSHUserPrivateKey(CredentialsScope scope, String username, PrivateKeySource privateKeySource,
                                  String passphrase,
                                  String description) {
        super(scope);
        this.username = username;
        this.description = description;
        this.privateKeySource = privateKeySource;
        this.passphrase = Secret.fromString(passphrase);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public String getPrivateKey() {
        if (privateKey == null) {
            String privateKey = privateKeySource.getPrivateKey();
            try {
                if (PuTTYKey.isPuTTYKeyFile(new StringReader(privateKey))) {
                    // strictly we should be encrypting the openssh version with the passphrase, but
                    // if the key we pass back does not have a passphrase, then the passphrase will not be
                    // checked, so not an issue.
                    privateKey = new PuTTYKey(new StringReader(privateKey),
                            passphrase == null ? "" : passphrase.getPlainText())
                            .toOpenSSH();
                }
            } catch (IOException e) {
                // ignore
            }
            this.privateKey = privateKey; // idempotent write
        }
        return privateKey;
    }

    @NonNull
    public PrivateKeySource getPrivateKeySource() {
        return privateKeySource;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public Secret getPassphrase() {
        return passphrase;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public String getUsername() {
        return StringUtils.isEmpty(username) ? System.getProperty("user.name") : username;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public String getDescription() {
        return StringUtils.isNotEmpty(description) ? description : "";
    }

    /**
     * {@inheritDoc}
     */
    @Extension
    public static class DescriptorImpl extends CredentialsDescriptor {

        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return Messages.BasicSSHUserPrivateKey_DisplayName();
        }

        public DescriptorExtensionList<PrivateKeySource, Descriptor<PrivateKeySource>> getPrivateKeySources() {
            return Hudson.getInstance().getDescriptorList(PrivateKeySource.class);
        }

        public BasicSSHUserPrivateKey fixInstance(BasicSSHUserPrivateKey instance) {
            return instance == null ? new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "", new DirectEntryPrivateKeySource(""), "", "") : instance;
        }
    }

    /**
     * A source of private keys
     */
    public static abstract class PrivateKeySource extends AbstractDescribableImpl<PrivateKeySource>
            implements Serializable {
        /**
         * Gets the private key from the source
         */
        @NonNull
        public abstract String getPrivateKey();
    }

    /**
     * Descriptor for a {@link PrivateKeySource}
     */
    public static abstract class PrivateKeySourceDescriptor extends Descriptor<PrivateKeySource> {
    }

    /**
     * Let the user enter the key directly via copy & paste
     */
    public static class DirectEntryPrivateKeySource extends PrivateKeySource {
        private final String privateKey;

        @DataBoundConstructor
        public DirectEntryPrivateKeySource(String privateKey) {
            this.privateKey = privateKey;
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public String getPrivateKey() {
            return privateKey;
        }

        /**
         * {@inheritDoc}
         */
        @Extension
        public static class DescriptorImpl extends PrivateKeySourceDescriptor {

            /**
             * {@inheritDoc}
             */
            @Override
            public String getDisplayName() {
                return Messages.BasicSSHUserPrivateKey_DirectEntryPrivateKeySourceDisplayName();
            }
        }
    }

    /**
     * Let the user reference a file on the disk.
     */
    public static class FileOnMasterPrivateKeySource extends PrivateKeySource {
        private final String privateKeyFile;

        @DataBoundConstructor
        public FileOnMasterPrivateKeySource(String privateKeyFile) {
            this.privateKeyFile = privateKeyFile;
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public String getPrivateKey() {
            try {
                return Hudson.getInstance().getRootPath().act(new ReadFileOnMaster(privateKeyFile));
            } catch (IOException e) {
                Logger.getLogger(getClass().getName())
                        .log(Level.WARNING, "Could not read private key file " + privateKeyFile, e);
            } catch (InterruptedException e) {
                Logger.getLogger(getClass().getName())
                        .log(Level.WARNING, "Could not read private key file " + privateKeyFile, e);
            }
            return "";
        }

        /**
         * Returns the private key file name.
         *
         * @return the private key file name.
         */
        public String getPrivateKeyFile() {
            return privateKeyFile;
        }

        /**
         * {@inheritDoc}
         */
        @Extension
        public static class DescriptorImpl extends PrivateKeySourceDescriptor {

            /**
             * {@inheritDoc}
             */
            @Override
            public String getDisplayName() {
                return Messages.BasicSSHUserPrivateKey_FileOnMasterPrivateKeySourceDisplayName();
            }
        }
    }

    /**
     * Let the user
     */
    public static class UsersPrivateKeySource extends PrivateKeySource {

        @DataBoundConstructor
        public UsersPrivateKeySource() {
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public String getPrivateKey() {
            try {
                return Hudson.getInstance().getRootPath().act(new ReadKeyOnMaster());
            } catch (IOException e) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Could not read private key", e);
            } catch (InterruptedException e) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Could not read private key", e);
            }
            return "";
        }

        /**
         * {@inheritDoc}
         */
        @Extension
        public static class DescriptorImpl extends PrivateKeySourceDescriptor {

            /**
             * {@inheritDoc}
             */
            @Override
            public String getDisplayName() {
                return Messages.BasicSSHUserPrivateKey_UsersPrivateKeySourceDisplayName();
            }
        }
    }

    public static class ReadFileOnMaster implements FilePath.FileCallable<String> {

        private final String path;

        public ReadFileOnMaster(String path) {
            this.path = path;
        }

        public String invoke(File f, VirtualChannel channel) throws IOException, InterruptedException {
            File key = new File(path);
            if (key.isFile()) {
                return FileUtils.readFileToString(key);
            }
            return "";
        }
    }

    public static class ReadKeyOnMaster implements FilePath.FileCallable<String> {

        public String invoke(File f, VirtualChannel channel) throws IOException, InterruptedException {
            File sshHome = new File(new File(System.getProperty("user.home")), ".ssh");
            for (String keyName : Arrays.asList("id_rsa", "id_dsa", "identity")) {
                File key = new File(sshHome, keyName);
                if (key.isFile()) {
                    return FileUtils.readFileToString(key);
                }
            }
            return "";
        }
    }
}
