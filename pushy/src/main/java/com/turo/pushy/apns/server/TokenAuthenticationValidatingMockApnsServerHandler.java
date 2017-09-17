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
import com.turo.pushy.apns.auth.AuthenticationToken;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.util.AsciiString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

class TokenAuthenticationValidatingMockApnsServerHandler extends ValidatingPushNotificationHandler {

    private final Map<String, ApnsVerificationKey> verificationKeysByKeyId;
    private final Map<ApnsVerificationKey, Set<String>> topicsByVerificationKey;

    private String expectedTeamId;

    private static final AsciiString APNS_TOPIC_HEADER = new AsciiString("apns-topic");
    private static final AsciiString APNS_AUTHORIZATION_HEADER = new AsciiString("authorization");

    private static final Logger log = LoggerFactory.getLogger(TokenAuthenticationValidatingMockApnsServerHandler.class);

    protected TokenAuthenticationValidatingMockApnsServerHandler(final Map<String, Set<String>> deviceTokensByTopic, final Map<String, Date> expirationTimestampsByDeviceToken, final Map<String, ApnsVerificationKey> verificationKeysByKeyId, final Map<ApnsVerificationKey, Set<String>> topicsByVerificationKey) {
        super(deviceTokensByTopic, expirationTimestampsByDeviceToken);

        this.verificationKeysByKeyId = verificationKeysByKeyId;
        this.topicsByVerificationKey = topicsByVerificationKey;
    }

    @Override
    protected void verifyAuthentication(final Http2Headers headers, final UUID apnsId) throws RejectedNotificationException {
        final String base64EncodedAuthenticationToken;
        {
            final CharSequence authorizationSequence = headers.get(APNS_AUTHORIZATION_HEADER);

            if (authorizationSequence != null) {
                final String authorizationString = authorizationSequence.toString();

                if (authorizationString.startsWith("bearer")) {
                    base64EncodedAuthenticationToken = authorizationString.substring("bearer".length()).trim();
                } else {
                    base64EncodedAuthenticationToken = null;
                }
            } else {
                base64EncodedAuthenticationToken = null;
            }
        }

        final AuthenticationToken authenticationToken = new AuthenticationToken(base64EncodedAuthenticationToken);
        final ApnsVerificationKey verificationKey = this.verificationKeysByKeyId.get(authenticationToken.getKeyId());

        // Have we ever heard of the key in question?
        if (verificationKey == null) {
            throw new RejectedNotificationException(RejectionReason.INVALID_PROVIDER_TOKEN, apnsId);
        }

        try {
            if (!authenticationToken.verifySignature(verificationKey)) {
                throw new RejectedNotificationException(RejectionReason.INVALID_PROVIDER_TOKEN, apnsId);
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            // This should never happen (here, at least) because we check keys at construction time. If something's
            // going to go wrong, it will go wrong before we ever get here.
            log.error("Failed to verify authentication token signature.", e);
            throw new RuntimeException(e);
        }

        // At this point, we've verified that the token is signed by somebody with the named team's private key. The
        // real APNs server only allows one team per connection, so if this is our first notification, we want to keep
        // track of the team that sent it so we can reject notifications from other teams, even if they're signed
        // correctly.
        if (this.expectedTeamId == null) {
            this.expectedTeamId = authenticationToken.getTeamId();
        }

        if (!this.expectedTeamId.equals(authenticationToken.getTeamId())) {
            throw new RejectedNotificationException(RejectionReason.INVALID_PROVIDER_TOKEN, apnsId);
        }

        if (authenticationToken.getIssuedAt().getTime() + MockApnsServer.AUTHENTICATION_TOKEN_EXPIRATION_MILLIS < System.currentTimeMillis()) {
            throw new RejectedNotificationException(RejectionReason.EXPIRED_PROVIDER_TOKEN, apnsId);
        }

        final String topic;
        {
            final CharSequence topicSequence = headers.get(APNS_TOPIC_HEADER);
            topic = (topicSequence != null) ? topicSequence.toString() : null;
        }

        final Set<String> topicsAllowedForVerificationKey = this.topicsByVerificationKey.get(verificationKey);

        if (topicsAllowedForVerificationKey == null || !topicsAllowedForVerificationKey.contains(topic)) {
            throw new RejectedNotificationException(RejectionReason.INVALID_PROVIDER_TOKEN, apnsId);
        }
    }
}
