# Version History

## Version 1.18 (Oct 07, 2019)

Update the minimum Jenkins core requirement to 2.190.1.

## Version 1.17.3 (Sep 24, 2019)
[JENKINS-50181](https://issues.jenkins-ci.org/browse/JENKINS-50181): Ensure private key ends with a newline when returning it

## Version 1.17.2 (Sep 10, 2019)

[PR-44](https://github.com/jenkinsci/ssh-credentials-plugin/pull/44): update JCasC to 1.30.

## Version 1.17.1 (Jul 10, 2019)

[JENKINS-50181](https://issues.jenkins-ci.org/browse/JENKINS-50181): ssh-agent/ssh-credentials-plugin failing because ssh-add expects a newline in the keyfile

## Version 1.17 (Jun 10, 2019)

Update the minimum Jenkins core requirement to 2.138.4

Update plugin dependencies to the recent versions

## Version 1.16 (Apr 22, 2019)

[PR-40](https://github.com/jenkinsci/ssh-credentials-plugin/pull/40): switch to use secret textarea form component for entering SSH private key in config form.

## Version 1.15 (Mar 08, 2019)

The plugin now requires Jenkins 2.73.3 and SSH Module 2.x

## Version 1.14 (Jun 25, 2018)

Fix security issue when Credentials Binding 1.13 or newer is installed

## Version 1.13 (Jan 31, 2017)

[JENKINS-23511](https://issues.jenkins-ci.org/browse/JENKINS-23511) InvalidClassException for SSHAuthenticator$1 when doing a git clone on an AIX slave

[JENKINS-35562](https://issues.jenkins-ci.org/browse/JENKINS-35562) Upgrade to Credentials 2.1.0+ API for populating credentials drop-down

[JENKINS-24613](https://issues.jenkins-ci.org/browse/JENKINS-24613) SSH Credentials should document the file names considered for UsersPrivateKeySource

[JENKINS-21283](https://issues.jenkins-ci.org/browse/JENKINS-21283) BasicSSHUserPrivateKey.getPassphrase breaks nullness contract of interface

[JENKINS-40003](https://issues.jenkins-ci.org/browse/JENKINS-40003) Add description to POM

[JENKINS-39836](https://issues.jenkins-ci.org/browse/JENKINS-39836) InvalidClassException for SSHAuthenticator$1 when doing a git clone on an Linux Z series, Linux P series, and Linux P LE series slaves

## Version 1.12 (May 11, 2016)

[JENKINS-26943](https://issues.jenkins-ci.org/browse/JENKINS-26943) BasicSSHUserPrivateKey.DirectEntryPrivateKeySource.privateKey stored in plaintext

Fix NPE in BasicSSHUserPrivateKey when the user has not configured a private key source

## Version 1.11 (Mar 30, 2015)

[JENKINS-26099](https://issues.jenkins-ci.org/browse/JENKINS-26099) Permit the ID of a newly configured private key credentials item to be defined.

## Version 1.10 (Oct 17, 2014)

Code to let slaves load private keys from files on the master did not work as intended.

Deprecating SSHUserListBoxModel.

## Version 1.9 (Aug 15, 2014)

Add safety to the Trilead SSH Authentication provider so that unknown key types do not cause authentication to bail ([JENKINS-24273](https://issues.jenkins-ci.org/browse/JENKINS-24273))

## Version 1.8 (Aug 11, 2014)

Add (experimental) support for ECDSA keys

## Version 1.7.1 (Jun 16, 2014)

Re-release of 1.7 (which failed to upload)

## Version 1.7 (Jun 16, 2014)

Update credentials plugin dependency to 1.14

Add support for snapshotting SSH credentials

## Version 1.6.1 (Feb 5, 2014)

Update credentials plugin dependency to 1.9.4

## Version 1.6 (Nov 8, 2013)

UI bugfix and update credentials plugin dependency to 1.9.2

## Version 1.5.1 (Oct 4, 2013)

Fix some annoying UI glitches that fell through the cracks

## Version 1.5 (Oct 4, 2013)

Add a readResolve to FileOnMasterPrivateKeySource that heals any borked upgrades where the key contents were set as the filename.

## Version 1.4 (Aug 30, 2013)

Add alternative API to allow overriding the username from SSHAuthenticator.newInstance(connector, user, username) - needed to support e.g. git@github.com SSH connections via JGit

## Version 1.3 (Aug 8, 2013)

Another binary incompatibility known to affect CloudBees DEV@cloud servers.

## Version 1.2 (Aug 8, 2013)

Binary incompatibility affecting older versions of the SSH Slaves plugin. ([JENKINS-19104](https://issues.jenkins-ci.org/browse/JENKINS-19104))

## Version 1.1 (Aug 7, 2013)

PuTTY key format regression. ([JENKINS-19104](https://issues.jenkins-ci.org/browse/JENKINS-19104))

## Version 1.0 (Aug 7, 2013)

Upgrade to Credentials Plugin 1.0 and migrate to new data types.

Any existing plugins that request credentials of type SSHUserPrivateKey explicitly will be unaffected.

If an existing plugin requests credentials of type BasicSSHUserPassword the resolution mechanism will handle the mapping to a concrete StandardUsernamePasswordCredentials transparently

If an existing plugin requests credentials of the base interface type SSHUser it will not be able to locate and StandardUsernamePasswordCredentials implementations and will need to be adapted to integrate correctly with the new class tree.

SSHAuthenticator.matcher() and SSHAuthenticator.matcher(Class< Connection type>) can be used to retrieve a CredentialsMatcher to narrow the search for appropriate credentials. 

**NOTE: This version requires the SSH Slaves plugin be upgraded to at least version 1.0 or it will break the installed SSH Slaves plugin.**

**NOTE: This version modifies the configuration data format from a format that can be read by version 0.4 to a format that can only be read by 1.0 or newer. It will not be possible to downgrade from 1.0 to a previous release without risking configuration data loss.** 

## Version 0.4 (Jul 1, 2013)

Made the authentication usable on slaves.

## Version 0.2 (Oct 25, 2012)

Add support for the JSch client library

## Version 0.1 (Feb 28, 2012)

Initial release 
