/*
 * Copyright (c) 2013-2017 Turo
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

package com.turo.pushy.apns.server;

import com.turo.pushy.apns.auth.ApnsVerificationKey;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ValidatingPushNotificationHandlerFactory implements PushNotificationHandlerFactory {

    private final Map<String, Set<String>> deviceTokensByTopic;
    private final Map<String, Date> expirationTimestampsByDeviceToken;

    private final Map<String, ApnsVerificationKey> verificationKeysByKeyId;
    private final Map<ApnsVerificationKey, Set<String>> topicsByVerificationKey;

    public ValidatingPushNotificationHandlerFactory(final Map<String, Set<String>> deviceTokensByTopic, final Map<String, Date> expirationTimestampsByDeviceToken, final Map<String, ApnsVerificationKey> verificationKeysByKeyId, final Map<ApnsVerificationKey, Set<String>> topicsByVerificationKey) {
        this.deviceTokensByTopic = deviceTokensByTopic;
        this.expirationTimestampsByDeviceToken = expirationTimestampsByDeviceToken;

        this.verificationKeysByKeyId = verificationKeysByKeyId;
        this.topicsByVerificationKey = topicsByVerificationKey;
    }

    @Override
    public PushNotificationHandler buildHandler(final SSLSession sslSession) {
        try {
            // This will throw an exception if the peer hasn't authenticated (i.e. we're expecting
            // token authentication).
            final String principalName = sslSession.getPeerPrincipal().getName();

            final Pattern pattern = Pattern.compile(".*UID=([^,]+).*");
            final Matcher matcher = pattern.matcher(principalName);

            final String baseTopic;

            if (matcher.matches()) {
                baseTopic = matcher.group(1);
            } else {
                throw new IllegalArgumentException("Client certificate does not specify a base topic.");
            }

            return new TlsAuthenticationValidatingPushNotificationHandler(
                    this.deviceTokensByTopic,
                    this.expirationTimestampsByDeviceToken,
                    baseTopic);

        } catch (final SSLPeerUnverifiedException e) {
            // No need for alarm; this is an expected case. If a client hasn't performed mutual TLS authentication, we
            // assume they want to use token authentication.
            return new TokenAuthenticationValidatingMockApnsServerHandler(
                    this.deviceTokensByTopic,
                    this.expirationTimestampsByDeviceToken,
                    this.verificationKeysByKeyId,
                    this.topicsByVerificationKey);
        }
    }
}
