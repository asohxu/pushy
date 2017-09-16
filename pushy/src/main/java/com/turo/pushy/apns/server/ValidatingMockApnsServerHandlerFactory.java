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

import io.netty.handler.codec.http2.Http2ConnectionHandler;
import io.netty.handler.codec.http2.Http2Settings;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.util.Date;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ValidatingMockApnsServerHandlerFactory implements MockApnsServerHandlerFactory {

    private final int maxConcurrentStreams;

    private final Map<String, Map<String, Date>> deviceTokenExpirationsByTopic;

    public ValidatingMockApnsServerHandlerFactory(final int maxConcurrentStreams, final Map<String, Map<String, Date>> deviceTokenExpirationsByTopic) {
        this.maxConcurrentStreams = maxConcurrentStreams;
        this.deviceTokenExpirationsByTopic = deviceTokenExpirationsByTopic;
    }

    @Override
    public Http2ConnectionHandler buildHandler(final SSLSession sslSession) {
        AbstractValidatingMockApnsServerHandler.AbstractMockApnsServerHandlerBuilder handlerBuilder;

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

            final TlsAuthenticationValidatingMockApnsServerHandler.TlsAuthenticationMockApnsServerHandlerBuilder tlsAuthenticationHandlerBuilder =
                    new TlsAuthenticationValidatingMockApnsServerHandler.TlsAuthenticationMockApnsServerHandlerBuilder();

            tlsAuthenticationHandlerBuilder.baseTopic(baseTopic);

            handlerBuilder = tlsAuthenticationHandlerBuilder;
        } catch (final SSLPeerUnverifiedException e) {
            // No need for alarm; this is an expected case
            final TokenAuthenticationValidatingMockApnsServerHandler.TokenAuthenticationMockApnsServerHandlerBuilder tokenAuthenticationHandlerBuilder =
                    new TokenAuthenticationValidatingMockApnsServerHandler.TokenAuthenticationMockApnsServerHandlerBuilder();

            /* tokenAuthenticationHandlerBuilder.verificationKeysByKeyId(MockApnsServer.this.verificationKeysByKeyId);
            tokenAuthenticationHandlerBuilder.topicsByVerificationKey(MockApnsServer.this.topicsByVerificationKey);
            tokenAuthenticationHandlerBuilder.emulateExpiredFirstToken(MockApnsServer.this.emulateExpiredFirstToken); */

            handlerBuilder = tokenAuthenticationHandlerBuilder;
        }

        return handlerBuilder
                .initialSettings(new Http2Settings().maxConcurrentStreams(this.maxConcurrentStreams))
                .deviceTokenExpirationsByTopic(this.deviceTokenExpirationsByTopic)
                .build();
    }
}
