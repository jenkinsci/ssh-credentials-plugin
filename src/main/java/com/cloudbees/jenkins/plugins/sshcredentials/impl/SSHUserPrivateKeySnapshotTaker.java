package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey.DirectEntryPrivateKeySource;
import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;

import hudson.Extension;
import hudson.util.Secret;

@Extension
public class SSHUserPrivateKeySnapshotTaker extends CredentialsSnapshotTaker<SSHUserPrivateKey> {
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
            return credentials;
        }
        final Secret passphrase = credentials.getPassphrase();
        return new BasicSSHUserPrivateKey(credentials.getScope(), credentials.getId(), credentials.getUsername(),
                new DirectEntryPrivateKeySource(credentials.getPrivateKeys()),
                passphrase == null ? null : passphrase.getEncryptedValue(), credentials.getDescription());
    }
}
