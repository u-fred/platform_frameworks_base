package com.android.internal.widget;

import android.app.admin.DevicePolicyManager;
import android.app.admin.PasswordMetrics;

import com.android.internal.widget.LockPatternUtils.LockDomain;

public class WrappedLockPatternUtils {
    private final LockPatternUtils mInner;
    private final LockDomain mLockDomain;

    public WrappedLockPatternUtils(LockPatternUtils inner, LockDomain lockDomain) {
        mInner = inner;
        mLockDomain = lockDomain;
    }

    public boolean hasSecureLockScreen() {
        return mInner.hasSecureLockScreen();
    }

    public boolean isCredentialsDisabledForUser(int userId) {
        return mInner.isCredentialsDisabledForUser(userId, mLockDomain == LockDomain.Primary);
    }

    public PasswordMetrics getRequestedPasswordMetrics(int userId) {
        return mInner.getRequestedPasswordMetrics(userId, mLockDomain);
    }

    public PasswordMetrics getRequestedPasswordMetrics(int userId, boolean deviceWideOnly) {
        return mInner.getRequestedPasswordMetrics(userId, mLockDomain, deviceWideOnly);
    }

    public @DevicePolicyManager.PasswordComplexity int getRequestedPasswordComplexity(int userId) {
        return mInner.getRequestedPasswordComplexity(userId, mLockDomain);
    }

    public @DevicePolicyManager.PasswordComplexity int getRequestedPasswordComplexity(int userId,
            boolean deviceWideOnly) {
        return mInner.getRequestedPasswordComplexity(userId, mLockDomain, deviceWideOnly);
    }

}
