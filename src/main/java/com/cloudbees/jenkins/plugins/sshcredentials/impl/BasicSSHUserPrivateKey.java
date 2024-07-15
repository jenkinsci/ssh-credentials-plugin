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
import hudson.RelativePath;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Items;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import jenkins.bouncycastle.api.PEMEncodable;
import jenkins.model.Jenkins;
import jenkins.security.FIPS140;
import net.jcip.annotations.GuardedBy;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * A simple username / password for use with SSH connections.
 */
public class BasicSSHUserPrivateKey extends BaseSSHUser implements SSHUserPrivateKey {

    /**
     * Ensure consistent serialization.
     */
    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger.getLogger(BasicSSHUserPrivateKey.class.getName());

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
        checkKeyFipsCompliance(this.privateKeySource.getPrivateKeys().get(0), this.passphrase);
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
        checkKeyFipsCompliance(privateKeySource.getPrivateKeys().get(0), passphrase);
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
            this.privateKeys = privateKeySource.getPrivateKeys().stream()
                    .map(privateKey -> privateKey.endsWith("\n") ? privateKey : privateKey + "\n")
                    .collect(Collectors.toList());
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
     * Checks if provided key is compliant with FIPS 140-2.
     * OpenSSH keys are not compliant (OpenSSH private key format ultimately contains a private key encrypted with a
     * non-standard version of PBKDF2 that uses bcrypt as its core hash function, also the structure that contains the key is not ASN.1.)
     * Only Ed25519 or RSA (with a minimum size of 1024, as it's used for identification, not signing) keys are accepted.
     * Method will log and launch an {@link IllegalArgumentException} if key is not compliant.
     * This method could be invoked when doing form validation once https://issues.jenkins.io/browse/JENKINS-73404 is done
     * @param privateKeySource the keySource
     * @param passphrase the secret used with the key (null if no secret provided)
     */
    private static void checkKeyFipsCompliance(String privateKeySource, Secret passphrase) {
        if (!FIPS140.useCompliantAlgorithms()) {
            return; // maintain existing behaviour if not in FIPS mode
        }
        if (StringUtils.isBlank(privateKeySource)) {
            return;
        }
        try {
            char[] pass = passphrase == null ? null : passphrase.getPlainText().toCharArray();
            if (pass == null || pass.length < 14) {
                LOGGER.log(Level.WARNING, Messages.BasicSSHUserPrivateKey_TooShortPassphraseFIPS());
                throw new IllegalArgumentException(Messages.BasicSSHUserPrivateKey_TooShortPassphraseFIPS());
            }
            PEMEncodable pem = PEMEncodable.decode(privateKeySource, pass);
            PrivateKey privateKey = pem.toPrivateKey();
            if (privateKey == null) { //somehow malformed key or unknown algorithm
                LOGGER.log(Level.WARNING, Messages.BasicSSHUserPrivateKey_UnknownAlgorithmFIPS());
                throw new IllegalArgumentException(Messages.BasicSSHUserPrivateKey_UnknownAlgorithmFIPS());
            }
            if (privateKey instanceof RSAPrivateKey) {
                if (((RSAPrivateKey) privateKey).getModulus().bitLength() < 1024) {
                    LOGGER.log(Level.WARNING, Messages.BasicSSHUserPrivateKey_InvalidKeySizeFIPS());
                    throw new IllegalArgumentException(Messages.BasicSSHUserPrivateKey_InvalidKeySizeFIPS());
                }
            } else if (!"Ed25519".equals(privateKey.getAlgorithm())) {
                // Using algorithm name to check elliptic curve, as EdECPrivateKey is not available in jdk11
                LOGGER.log(Level.WARNING, Messages.BasicSSHUserPrivateKey_InvalidAlgorithmFIPS(privateKey.getAlgorithm()));
                throw new IllegalArgumentException( Messages.BasicSSHUserPrivateKey_InvalidAlgorithmFIPS(privateKey.getAlgorithm()));
            }
        } catch (IOException ex) { // OpenSSH keys will raise this
            LOGGER.log(Level.WARNING, Messages.BasicSSHUserPrivateKey_InvalidKeyFormatFIPS());
            throw new IllegalArgumentException(Messages.BasicSSHUserPrivateKey_InvalidKeyFormatFIPS());
        } catch (UnrecoverableKeyException ex) {
            LOGGER.log(Level.WARNING, Messages.BasicSSHUserPrivateKey_WrongPassphraseFIPS());
            throw new IllegalArgumentException(Messages.BasicSSHUserPrivateKey_WrongPassphraseFIPS());
        }
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

            @RequirePOST
            public FormValidation doCheckPrivateKey (@QueryParameter String privateKey,
                                                     @RelativePath("..") @QueryParameter String passphrase) {
                try {
                    checkKeyFipsCompliance(privateKey, Secret.fromString(passphrase));
                    return FormValidation.ok();
                } catch (IllegalArgumentException ex) {
                    return FormValidation.error(ex, ex.getMessage());
                }

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
