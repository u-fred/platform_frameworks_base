package com.android.internal.widget;

import android.app.admin.DevicePolicyManager;
import android.app.admin.PasswordMetrics;

import com.android.internal.widget.LockPatternUtils.AuthType;

public class WrappedLockPatternUtils {
    private final LockPatternUtils mInner;
    private final AuthType mAuthType;

    public WrappedLockPatternUtils(LockPatternUtils inner, AuthType authType) {
        mInner = inner;
        mAuthType = authType;
    }

    public boolean hasSecureLockScreen() {
        return mInner.hasSecureLockScreen();
    }

    public boolean isCredentialsDisabledForUser(int userId) {
        return mInner.isCredentialsDisabledForUser(userId, mAuthType == AuthType.PRIMARY);
    }

    public PasswordMetrics getRequestedPasswordMetrics(int userId, boolean deviceWideOnly) {
        return mInner.getRequestedPasswordMetrics(userId,
                mAuthType == AuthType.PRIMARY, deviceWideOnly);
    }

    public @DevicePolicyManager.PasswordComplexity int getRequestedPasswordComplexity(int userId,
            boolean deviceWideOnly) {
        return mInner.getRequestedPasswordComplexity(userId,
                mAuthType == AuthType.PRIMARY, deviceWideOnly);
    }

}
