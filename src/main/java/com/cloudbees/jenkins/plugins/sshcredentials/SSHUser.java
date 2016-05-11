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
package com.cloudbees.jenkins.plugins.sshcredentials;

import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;

/**
 * Represents a user name and a secret (password/privateKey/etc) needed to perform an authentication in an SSH
 * connection.
 * <p>
 * This interface is a base interface that defines commonality across all the modes of authentications,
 * then the subtype defines a specific type of secret.
 * </p>
 *
 * @see SSHUserPassword
 * @see SSHUserPrivateKey
 * @see SSHUserListBoxModel
 * @deprecated Use {@link StandardUsernameCredentials} as the common class.
 */
@Deprecated
public interface SSHUser extends StandardUsernameCredentials {

}
