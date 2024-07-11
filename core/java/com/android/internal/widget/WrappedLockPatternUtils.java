package com.android.internal.widget;

import android.app.admin.DevicePolicyManager;
import android.app.admin.PasswordMetrics;

import com.android.internal.widget.LockPatternUtils.CredentialPurpose;

public class WrappedLockPatternUtils {
    private final LockPatternUtils mInner;
    private final CredentialPurpose mPurpose;

    public WrappedLockPatternUtils(LockPatternUtils inner, CredentialPurpose purpose) {
        mInner = inner;
        mPurpose = purpose;
    }

    public boolean hasSecureLockScreen() {
        return mInner.hasSecureLockScreen();
    }

    public boolean isCredentialsDisabledForUser(int userId) {
        return mInner.isCredentialsDisabledForUser(userId, mPurpose == CredentialPurpose.PRIMARY);
    }

    public PasswordMetrics getRequestedPasswordMetrics(int userId, boolean deviceWideOnly) {
        return mInner.getRequestedPasswordMetrics(userId,
                mPurpose == CredentialPurpose.PRIMARY, deviceWideOnly);
    }

    public @DevicePolicyManager.PasswordComplexity int getRequestedPasswordComplexity(int userId,
            boolean deviceWideOnly) {
        return mInner.getRequestedPasswordComplexity(userId,
                mPurpose == CredentialPurpose.PRIMARY, deviceWideOnly);
    }

}
