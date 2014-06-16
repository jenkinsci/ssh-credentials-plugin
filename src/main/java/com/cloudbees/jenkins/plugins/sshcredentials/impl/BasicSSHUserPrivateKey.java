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
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.FilePath;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.remoting.VirtualChannel;
import hudson.util.Secret;
import net.jcip.annotations.GuardedBy;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.putty.PuTTYKey;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A simple username / password for use with SSH connections.
 */
public class BasicSSHUserPrivateKey extends BaseSSHUser implements SSHUserPrivateKey {

    /**
     * Ensure consistent serialization.
     */
    private static final long serialVersionUID = 1L;

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
    @GuardedBy("this")
    private transient List<String> privateKeys;

    /**
     * The maximum amount of time to cache the private keys before refreshing.
     *
     * @since 1.1
     */
    @GuardedBy("this")
    private transient long privateKeysLastModified;

    /**
     * Constructor for stapler.
     *
     * @param scope            the credentials scope
     * @param username         the username.
     * @param privateKeySource the private key.
     * @param passphrase       the password.
     * @param description      the description.
     */
    @DataBoundConstructor
    public BasicSSHUserPrivateKey(CredentialsScope scope, String id, String username, PrivateKeySource privateKeySource,
                                  String passphrase,
                                  String description) {
        super(scope, id, username, description);
        this.privateKeySource = privateKeySource;
        this.passphrase = Secret.fromString(passphrase);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public String getPrivateKey() {
        List<String> privateKeys = getPrivateKeys();
        return privateKeys.isEmpty() ? "" : privateKeys.get(0);
    }

    @NonNull
    public synchronized List<String> getPrivateKeys() {
        long lastModified = privateKeySource.getPrivateKeysLastModified();
        if (privateKeys == null || privateKeys.isEmpty() || lastModified > privateKeysLastModified) {
            List<String> privateKeys = new ArrayList<String>();
            for (String privateKey : privateKeySource.getPrivateKeys()) {
                try {
                    if (PuTTYKey.isPuTTYKeyFile(new StringReader(privateKey))) {
                        // strictly we should be encrypting the openssh version with the passphrase, but
                        // if the key we pass back does not have a passphrase, then the passphrase will not be
                        // checked, so not an issue.
                        privateKeys.add(new PuTTYKey(new StringReader(privateKey),
                                passphrase == null ? "" : passphrase.getPlainText())
                                .toOpenSSH());
                    } else {
                        privateKeys.add(privateKey);
                    }
                } catch (IOException e) {
                    // ignore
                }
            }
            this.privateKeys = privateKeys;
            this.privateKeysLastModified = lastModified;
        }
        return privateKeys;
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
    @Override
    public int hashCode() {
        return super.hashCode();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
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
            return instance == null ? new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, null, "",
                    new DirectEntryPrivateKeySource(""), "",

                    "") : instance;
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
        public abstract List<String> getPrivateKeys();

        /**
         * Returns a revision count or a timestamp (in either case strictly increasing after changes to the private
         * keys)
         *
         * @return a revision count or a timestamp.
         * @since 1.4
         */
        public long getPrivateKeysLastModified() {
            return 1; // pick a default that is greater than the field initializer for constant sources.
        }

        /**
         * Returns {@code true} if and only if the source is self contained.
         *
         * @return {@code true} if and only if the source is self contained.
         * @since 1.7
         */
        public boolean isSnapshotSource() {
            return false;
        }

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
        /**
         * Ensure consistent serialization.
         */
        private static final long serialVersionUID = 1L;

        private final String privateKey;

        @DataBoundConstructor
        public DirectEntryPrivateKeySource(String privateKey) {
            this.privateKey = privateKey;
        }

        public DirectEntryPrivateKeySource(List<String> privateKeys) {
            this(StringUtils.join(privateKeys, "\f"));
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public List<String> getPrivateKeys() {
            return Arrays.asList(StringUtils.split(privateKey, "\f"));
        }

        /**
         * Returns the private key.
         *
         * @return the private key.
         */
        @SuppressWarnings("unused") // used by Jelly EL
        public String getPrivateKey() {
            return privateKey;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isSnapshotSource() {
            return true;
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
        /**
         * Ensure consistent serialization.
         */
        private static final long serialVersionUID = 1L;

        /**
         * Our logger
         */
        private static final Logger LOGGER = Logger.getLogger(FileOnMasterPrivateKeySource.class.getName());

        /**
         * The path to the private key.
         */
        private final String privateKeyFile;

        /**
         * When any of the key files was last modified.
         */
        private transient volatile long lastModified;

        /**
         * When we will next try a refresh of the status.
         */
        private transient volatile long nextCheckLastModified;


        @DataBoundConstructor
        public FileOnMasterPrivateKeySource(String privateKeyFile) {
            this.privateKeyFile = privateKeyFile;
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public List<String> getPrivateKeys() {
            try {
                return Collections
                        .singletonList(Hudson.getInstance().getRootPath().act(new ReadFileOnMaster(privateKeyFile)));
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Could not read private key file " + privateKeyFile, e);
            } catch (InterruptedException e) {
                LOGGER.log(Level.WARNING, "Could not read private key file " + privateKeyFile, e);
            }
            return Collections.emptyList();
        }

        /**
         * Returns the private key file name.
         *
         * @return the private key file name.
         */
        public String getPrivateKeyFile() {
            return privateKeyFile;
        }

        private Object readResolve() {
            if (privateKeyFile != null
                    && privateKeyFile.startsWith("---")
                    && privateKeyFile.contains("---BEGIN")
                    && privateKeyFile.contains("---END")) {
                // this is a borked upgrade, not actually the file name but is actually the key contents
                return new DirectEntryPrivateKeySource(privateKeyFile);
            }
            return this;
        }

        @Override
        public long getPrivateKeysLastModified() {
            if (nextCheckLastModified > System.currentTimeMillis() || lastModified < 0) {
                try {
                    lastModified = Hudson.getInstance().getRootPath().act(new LastModifiedOnMaster(privateKeyFile));
                } catch (NullPointerException e) {
                    LOGGER.log(Level.WARNING, "Could not stat private key file " + privateKeyFile, e);
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Could not stat private key file " + privateKeyFile, e);
                } catch (InterruptedException e) {
                    LOGGER.log(Level.WARNING, "Could not stat private key file " + privateKeyFile, e);
                }
                nextCheckLastModified = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(30);
            }
            return lastModified;
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
        /**
         * Ensure consistent serialization.
         */
        private static final long serialVersionUID = 1L;

        /**
         * Our logger
         */
        private static final Logger LOGGER = Logger.getLogger(UsersPrivateKeySource.class.getName());

        /**
         * When any of the key files was last modified.
         */
        private transient volatile long lastModified;

        /**
         * When we will next try a refresh of the status.
         */
        private transient volatile long nextCheckLastModified;

        @DataBoundConstructor
        public UsersPrivateKeySource() {
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public List<String> getPrivateKeys() {
            try {
                return Hudson.getInstance().getRootPath().act(new ReadKeyOnMaster());
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Could not read private key", e);
            } catch (InterruptedException e) {
                LOGGER.log(Level.WARNING, "Could not read private key", e);
            }
            return Collections.emptyList();
        }

        @Override
        public long getPrivateKeysLastModified() {
            if (nextCheckLastModified > System.currentTimeMillis() || lastModified < 0) {
                try {
                    lastModified = Hudson.getInstance().getRootPath().act(new KeyLastModifiedOnMaster());
                } catch (NullPointerException e) {
                    LOGGER.log(Level.WARNING, "Could not stat private keys", e);
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Could not stat private keys", e);
                } catch (InterruptedException e) {
                    LOGGER.log(Level.WARNING, "Could not stat private keys", e);
                }
                nextCheckLastModified = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(30);
            }
            return lastModified;
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
        /**
         * Ensure consistent serialization.
         */
        private static final long serialVersionUID = 1L;

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

    public static class ReadKeyOnMaster implements FilePath.FileCallable<List<String>> {

        /**
         * Ensure consistent serialization.
         */
        private static final long serialVersionUID = 2L;

        public List<String> invoke(File f, VirtualChannel channel) throws IOException, InterruptedException {
            List<String> result = new ArrayList<String>();
            File sshHome = new File(new File(System.getProperty("user.home")), ".ssh");
            for (String keyName : Arrays.asList("id_rsa", "id_dsa", "identity")) {
                File key = new File(sshHome, keyName);
                if (key.isFile()) {
                    result.add(FileUtils.readFileToString(key));
                }
            }
            return result;
        }
    }

    public static class LastModifiedOnMaster implements FilePath.FileCallable<Long> {

        /**
         * Ensure consistent serialization.
         */
        private static final long serialVersionUID = 2L;

        private final List<String> files;

        public LastModifiedOnMaster(String... files) {
            this(Arrays.asList(files));
        }

        public LastModifiedOnMaster(List<String> files) {
            this.files = new ArrayList<String>(files);
        }

        public Long invoke(File f, VirtualChannel channel) throws IOException, InterruptedException {
            long lastModified = Long.MIN_VALUE;
            for (String path : files) {
                File file = new File(path);
                if (file.exists()) {
                    lastModified = Math.max(lastModified, file.lastModified());
                }
            }
            return lastModified;
        }
    }

    public static class KeyLastModifiedOnMaster implements FilePath.FileCallable<Long> {

        /**
         * Ensure consistent serialization.
         */
        private static final long serialVersionUID = 2L;

        public Long invoke(File f, VirtualChannel channel) throws IOException, InterruptedException {
            long lastModified = Long.MIN_VALUE;
            File sshHome = new File(new File(System.getProperty("user.home")), ".ssh");
            for (String keyName : Arrays.asList("id_rsa", "id_dsa", "identity")) {
                File file = new File(sshHome, keyName);
                if (file.exists()) {
                    lastModified = Math.max(lastModified, file.lastModified());
                }
            }
            return lastModified;
        }
    }

    /**
     * @since 1.7
     */
    @Extension
    public static class CredentialsSnapshotTakerImpl extends CredentialsSnapshotTaker<SSHUserPrivateKey> {

        /**
         * {@inheritDoc}
         */
        @Override
        public Class<SSHUserPrivateKey> type() {
            return SSHUserPrivateKey.class;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public SSHUserPrivateKey snapshot(SSHUserPrivateKey credentials) {
            if (credentials instanceof BasicSSHUserPrivateKey) {
                final PrivateKeySource keySource = ((BasicSSHUserPrivateKey) credentials).getPrivateKeySource();
                if (keySource.isSnapshotSource()) {
                    return credentials;
                }
            }
            return new BasicSSHUserPrivateKey(credentials.getScope(), credentials.getId(), credentials.getUsername(),
                    new DirectEntryPrivateKeySource(credentials.getPrivateKeys()),
                    credentials.getPassphrase().getEncryptedValue(), credentials.getDescription());
        }
    }
}
