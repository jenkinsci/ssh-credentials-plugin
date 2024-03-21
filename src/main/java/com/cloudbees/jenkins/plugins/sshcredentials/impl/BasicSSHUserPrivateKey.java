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
import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Items;
import hudson.util.Secret;
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

import jenkins.model.Jenkins;
import net.jcip.annotations.GuardedBy;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.putty.PuTTYKey;
import org.kohsuke.stapler.DataBoundConstructor;

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
        this.privateKeySource = privateKeySource == null ? new DirectEntryPrivateKeySource("") : privateKeySource;
        this.passphrase = fixEmpty(passphrase == null ? null : Secret.fromString(passphrase));
    }

    private static Secret fixEmpty(Secret secret) {
        return secret == null ? null : secret.getPlainText().isEmpty() ? null : secret;
    }

    @Override
    protected synchronized Object readResolve() {
        if (privateKeySource == null) {
            Secret passphrase = getPassphrase();
            if (privateKeys != null) {
                return new BasicSSHUserPrivateKey(
                        getScope(),
                        getId(),
                        getUsername(),
                        new DirectEntryPrivateKeySource(privateKeys),
                        passphrase == null ? null : passphrase.getEncryptedValue(),
                        getDescription()
                );
            }
            return new BasicSSHUserPrivateKey(
                    getScope(),
                    getId(),
                    getUsername(),
                    new DirectEntryPrivateKeySource(""),
                    passphrase == null ? null : passphrase.getEncryptedValue(),
                    getDescription()
            );
        }
        if (passphrase != null && fixEmpty(passphrase) == null) {
            return new BasicSSHUserPrivateKey(
                    getScope(),
                    getId(),
                    getUsername(),
                    privateKeySource,
                    null,
                    getDescription()
            );
        }
        return super.readResolve();
    }

    @NonNull
    public synchronized List<String> getPrivateKeys() {
        if (privateKeySource == null) {
            return Collections.emptyList();
        }
        long lastModified = privateKeySource.getPrivateKeysLastModified();
        if (privateKeys == null || privateKeys.isEmpty() || lastModified > privateKeysLastModified) {
            List<String> privateKeys = new ArrayList<>();
            for (String privateKey : privateKeySource.getPrivateKeys()) {
                try {
                    boolean accepted = false;
                    for (PrivateKeyReader reader : ExtensionList.lookup(PrivateKeyReader.class)) {
                        if(reader.accept(privateKey)) {
                            privateKeys.add(reader.toOpenSSH(privateKey, passphrase));
                            accepted = true;
                        }
                    }
                    if (accepted){
                        continue;
                    }
                    privateKeys.add(privateKey.endsWith("\n") ? privateKey : privateKey + "\n");

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
        return privateKeySource == null ? new DirectEntryPrivateKeySource("") : privateKeySource;
    }

    /**
     * {@inheritDoc}
     */
    @CheckForNull
    public Secret getPassphrase() {
        return passphrase;
    }

    /**
     * {@inheritDoc}
     */
    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.BasicSSHUserPrivateKey_DisplayName();
        }

        public DescriptorExtensionList<PrivateKeySource, Descriptor<PrivateKeySource>> getPrivateKeySources() {
            return Jenkins.get().getDescriptorList(PrivateKeySource.class);
        }

        /**
         * {@inheritDoc}
         */
        public String getIconClassName() {
            return "symbol-fingerprint";
        }
    }

    /**
     * A source of private keys
     */
    public static abstract class PrivateKeySource extends AbstractDescribableImpl<PrivateKeySource> {
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
         * @deprecated no more used since FileOnMaster- and Users- PrivateKeySource are deprecated too
         */
        @Deprecated
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
     * Let the user enter the key directly via copy &amp; paste
     */
    public static class DirectEntryPrivateKeySource extends PrivateKeySource implements Serializable {
        /**
         * Ensure consistent serialization.
         */
        private static final long serialVersionUID = 1L;

        private final Secret privateKey;

        public DirectEntryPrivateKeySource(String privateKey) {
            this(Secret.fromString(privateKey.endsWith("\n") ? privateKey : privateKey + "\n"));
        }

        @DataBoundConstructor
        public DirectEntryPrivateKeySource(Secret privateKey) {
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
            String privateKeys = Secret.toString(privateKey);
            return StringUtils.isBlank(privateKeys)
                    ? Collections.emptyList()
                    : Arrays.asList(StringUtils.split(privateKeys, "\f"));
        }

        /**
         * Returns the private key.
         *
         * @return the private key.
         */
        @SuppressWarnings("unused") // used by Jelly EL
        public Secret getPrivateKey() {
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
            @NonNull
            @Override
            public String getDisplayName() {
                return Messages.BasicSSHUserPrivateKey_DirectEntryPrivateKeySourceDisplayName();
            }
        }
    }

    /**
     * Let the user reference a file on the disk.
     * @deprecated This approach has security vulnerability and should be migrated to {@link DirectEntryPrivateKeySource}
     */
    @Deprecated
    public static class FileOnMasterPrivateKeySource extends PrivateKeySource {

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

        public FileOnMasterPrivateKeySource(String privateKeyFile) {
            this.privateKeyFile = privateKeyFile;
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public List<String> getPrivateKeys() {
            if (privateKeyFile != null) {
                File key = new File(privateKeyFile);
                if (key.isFile()) {
                    try {
                        return Collections.singletonList(FileUtils.readFileToString(key));
                    } catch (IOException e) {
                        LOGGER.log(Level.WARNING, "Could not read private key file " + privateKeyFile, e);
                    }
                }
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

            Jenkins.get().checkPermission(Jenkins.RUN_SCRIPTS);

            LOGGER.log(Level.INFO, "SECURITY-440: Migrating FileOnMasterPrivateKeySource to DirectEntryPrivateKeySource");
            // read the content of the file and then migrate to Direct
            return new DirectEntryPrivateKeySource(getPrivateKeys());
        }

        @Override
        public long getPrivateKeysLastModified() {
            if (nextCheckLastModified > System.currentTimeMillis() || lastModified < 0) {
                lastModified = Long.MIN_VALUE;
                if (privateKeyFile != null) {
                    File file = new File(privateKeyFile);
                    if (file.exists()) {
                        lastModified = file.lastModified();
                    }
                }
                nextCheckLastModified = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(30);
            }
            return lastModified;
        }
    }

    /**
     * Let the user
     * @deprecated This approach has security vulnerability and should be migrated to {@link DirectEntryPrivateKeySource}
     */
    @Deprecated
    public static class UsersPrivateKeySource extends PrivateKeySource {

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

        private List<File> files() {
            List<File> files = new ArrayList<>();
            File sshHome = new File(new File(System.getProperty("user.home")), ".ssh");
            for (String keyName : Arrays.asList("id_ecdsa", "id_ed25519", "id_rsa", "id_dsa", "identity")) {
                File key = new File(sshHome, keyName);
                if (key.isFile()) {
                    files.add(key);
                }
            }
            return files;
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public List<String> getPrivateKeys() {
            List<String> keys = new ArrayList<>();
            for (File file : files()) {
                try {
                    keys.add(FileUtils.readFileToString(file));
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Could not read private key", e);
                }
            }
            return keys;
        }

        @Override
        public long getPrivateKeysLastModified() {
            if (nextCheckLastModified > System.currentTimeMillis() || lastModified < 0) {
                lastModified = Long.MIN_VALUE;
                for (File file : files()) {
                    lastModified = Math.max(lastModified, file.lastModified());
                }
                nextCheckLastModified = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(30);
            }
            return lastModified;
        }

        private Object readResolve() {
            Jenkins.get().checkPermission(Jenkins.RUN_SCRIPTS);

            LOGGER.log(Level.INFO, "SECURITY-440: Migrating UsersPrivateKeySource to DirectEntryPrivateKeySource");
            // read the content of the file and then migrate to Direct
            return new DirectEntryPrivateKeySource(getPrivateKeys());
        }
    }

    static {
        // the critical field allow the permission check to make the XML read to fail completely in case of violation
        Items.XSTREAM2.addCriticalField(BasicSSHUserPrivateKey.class, "privateKeySource");
    }
}
