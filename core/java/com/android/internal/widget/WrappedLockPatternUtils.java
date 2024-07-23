package com.android.internal.widget;

import static com.android.internal.widget.LockDomain.Secondary;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.app.admin.DevicePolicyManager;
import android.app.admin.PasswordMetrics;
import android.content.Context;

// TODO: Verify exceptions thrown when calling method with Secondary where Secondary it not
//  supported.
// TODO: Verify this only includes methods that are actually being used.

public class WrappedLockPatternUtils {
    private final LockPatternUtils mInner;
    private final LockDomain mLockDomain;

    public WrappedLockPatternUtils(LockPatternUtils inner, LockDomain lockDomain) {
        mInner = inner;
        mLockDomain = lockDomain;
    }
    public WrappedLockPatternUtils(Context context, LockDomain lockDomain) {
        mInner = new LockPatternUtils(context);
        mLockDomain = lockDomain;
    }

    public LockPatternUtils getInner() {
        return mInner;
    }

    public LockDomain getLockDomain() {
        return mLockDomain;
    }

    public boolean hasSecureLockScreen() {
        return mInner.hasSecureLockScreen();
    }

    public boolean isCredentialsDisabledForUser(int userId) {
        return mInner.isCredentialsDisabledForUser(userId, mLockDomain);
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

    public boolean isBiometricAllowedForUser(int userId) {
        return mInner.isBiometricAllowedForUser(userId);
    }

    public int getCurrentFailedPasswordAttempts(int userId) {
        return mInner.getCurrentFailedPasswordAttempts(userId, mLockDomain);
    }

    public int getMaximumFailedPasswordsForWipe(int userId) {
        return mInner.getMaximumFailedPasswordsForWipe(userId, mLockDomain);
    }

    public void reportFailedPasswordAttempt(int userId) {
        mInner.reportFailedPasswordAttempt(userId, mLockDomain);
    }

    @Deprecated
    public int getKeyguardStoredPasswordQuality(int userHandle) {
        return mInner.getKeyguardStoredPasswordQuality(userHandle, mLockDomain);
    }

    public long getLockoutAttemptDeadline(int userId) {
        return mInner.getLockoutAttemptDeadline(userId, mLockDomain);
    }

    public long setLockoutAttemptDeadline(int userId, int timeoutMs) {
        return mInner.setLockoutAttemptDeadline(userId, mLockDomain, timeoutMs);
    }

    public @DevicePolicyManager.PasswordComplexity int getRequestedPasswordComplexity(int userId,
            boolean deviceWideOnly) {
        return mInner.getRequestedPasswordComplexity(userId, mLockDomain, deviceWideOnly);
    }

    public boolean isSecure(int userId) {
        return mInner.isSecure(userId, mLockDomain);
    }

    public boolean setLockCredential(@NonNull LockscreenCredential newCredential,
            @NonNull LockscreenCredential savedCredential, int userHandle) {
        return mInner.setLockCredential(newCredential, savedCredential, mLockDomain, userHandle);
    }

    @NonNull
    public VerifyCredentialResponse verifyCredential(@NonNull LockscreenCredential credential,
            int userId, @LockPatternUtils.VerifyFlag int flags) {
        return mInner.verifyCredential(credential, mLockDomain, userId, flags);
    }

    public boolean checkCredential(@NonNull LockscreenCredential credential, int userId,
            @Nullable LockPatternUtils.CheckCredentialProgressCallback progressCallback)
            throws LockPatternUtils.RequestThrottledException {
        return mInner.checkCredential(credential, mLockDomain, userId, progressCallback);
    }

    public void setSeparateProfileChallengeEnabled(int userHandle, boolean enabled,
            LockscreenCredential profilePassword) {
        if (mLockDomain == Secondary) {
            throw new IllegalStateException();
        }
        mInner.setSeparateProfileChallengeEnabled(userHandle, enabled, profilePassword);
    }

    public boolean isVisiblePatternEnabled(int userId) {
        if (mLockDomain == Secondary) {
            throw new IllegalStateException();
        }
        return mInner.isVisiblePatternEnabled(userId);
    }

    public boolean isLockPatternEnabled(int userId) {
        if (mLockDomain == Secondary) {
            throw new IllegalStateException();
        }
        return mInner.isLockPatternEnabled(userId);
    }

    public boolean checkPasswordHistory(byte[] passwordToCheck, byte[] hashFactor, int userId) {
        return mInner.checkPasswordHistory(passwordToCheck, hashFactor, userId, mLockDomain);
    }

    public byte[] getPasswordHistoryHashFactor(@NonNull LockscreenCredential currentPassword,
            int userId) {
        return mInner.getPasswordHistoryHashFactor(currentPassword, userId);
    }

    public void setAutoPinConfirm(boolean enabled, int userId) {
        mInner.setAutoPinConfirm(enabled, userId, mLockDomain);
    }
    @NonNull
    public VerifyCredentialResponse verifyTiedProfileChallenge(
            @NonNull LockscreenCredential credential, int userId, @LockPatternUtils.VerifyFlag int flags) {
        if (mLockDomain == Secondary) {
            throw new IllegalStateException();
        }
        return mInner.verifyTiedProfileChallenge(credential, userId, flags);
    }

    public @LockPatternUtils.CredentialType int getCredentialTypeForUser(int userHandle) {
        return mInner.getCredentialTypeForUser(userHandle, mLockDomain);
    }

    public int getPinLength(int userId) {
        return mInner.getPinLength(userId, mLockDomain);
    }

    public boolean isAutoPinConfirmEnabled(int userId) {
        return mInner.isAutoPinConfirmEnabled(userId, mLockDomain);
    }

    public boolean refreshStoredPinLength(int userId) {
        return mInner.refreshStoredPinLength(userId, mLockDomain);
    }

    public void setVisiblePatternEnabled(boolean enabled, int userId) {
        if (mLockDomain == Secondary) {
            throw new IllegalStateException();
        }
        mInner.setVisiblePatternEnabled(enabled, userId);
    }

    public void setPinEnhancedPrivacyEnabled(boolean enabled, int userId) {
        mInner.setPinEnhancedPrivacyEnabled(enabled, userId, mLockDomain);
    }

    public boolean isPinEnhancedPrivacyEnabled(int userId) {
        return mInner.isPinEnhancedPrivacyEnabled(userId, mLockDomain);
    }

    public boolean getPowerButtonInstantlyLocks(int userId) {
        if (mLockDomain == Secondary) {
            throw new IllegalStateException();
        }
        return mInner.getPowerButtonInstantlyLocks(userId);
    }

    public void setPowerButtonInstantlyLocks(boolean enabled, int userId) {
        if (mLockDomain == Secondary) {
            throw new IllegalStateException();
        }
        mInner.setPowerButtonInstantlyLocks(enabled, userId);
    }

    public boolean isSeparateProfileChallengeEnabled(int userHandle) {
        return mInner.isSeparateProfileChallengeEnabled(userHandle);
    }

    public void setLockScreenDisabled(boolean disable, int userId) {
        mInner.setLockScreenDisabled(disable, userId);
    }

    public boolean isLockScreenDisabled(int userId) {
        return mInner.isLockScreenDisabled(userId, mLockDomain);
    }

    public boolean checkUserSupportsBiometricSecondFactor(int userId) {
        return mInner.checkUserSupportsBiometricSecondFactor(userId);
    }

    public boolean checkUserSupportsBiometricSecondFactor(int userId, boolean throwIfNotSupport) {
        return mInner.checkUserSupportsBiometricSecondFactor(userId, throwIfNotSupport);
    }

}
