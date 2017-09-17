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

import java.util.Date;
import java.util.Objects;
import java.util.UUID;

public class RejectedNotificationException extends Exception {
    private final RejectionReason errorReason;
    private final UUID apnsId;
    private final Date deviceTokenExpirationTimestamp;

    public RejectedNotificationException(final RejectionReason errorReason, final UUID apnsId) {
        this(errorReason, apnsId, null);
    }

    public RejectedNotificationException(final RejectionReason errorReason, final UUID apnsId, final Date deviceTokenExpirationTimestamp) {
        Objects.requireNonNull(errorReason, "Error reason must not be null.");

        this.errorReason = errorReason;
        this.deviceTokenExpirationTimestamp = deviceTokenExpirationTimestamp;

        this.apnsId = apnsId != null ? apnsId : UUID.randomUUID();
    }

    RejectionReason getRejectionReason() {
        return errorReason;
    }

    Date getDeviceTokenExpirationTimestamp() {
        return deviceTokenExpirationTimestamp;
    }

    UUID getApnsId() {
        return apnsId;
    }
}
