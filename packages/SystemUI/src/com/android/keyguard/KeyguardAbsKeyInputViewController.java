/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.keyguard;

import static com.android.internal.util.LatencyTracker.ACTION_CHECK_CREDENTIAL;
import static com.android.internal.util.LatencyTracker.ACTION_CHECK_CREDENTIAL_UNLOCKED;
import static com.android.keyguard.KeyguardAbsKeyInputView.MINIMUM_PASSWORD_LENGTH_BEFORE_REPORT;

import android.content.res.ColorStateList;
import android.os.AsyncTask;
import android.os.CountDownTimer;
import android.os.SystemClock;
import android.util.Log;
import android.util.PluralsMessageFormatter;
import android.view.KeyEvent;

import com.android.internal.util.LatencyTracker;
import com.android.internal.widget.LockPatternChecker;
import com.android.internal.widget.LockPatternUtils;
import com.android.internal.widget.LockscreenCredential;
import com.android.keyguard.EmergencyButtonController.EmergencyButtonCallback;
import com.android.keyguard.KeyguardAbsKeyInputView.KeyDownListener;
import com.android.keyguard.KeyguardSecurityModel.SecurityMode;
import com.android.systemui.classifier.FalsingClassifier;
import com.android.systemui.classifier.FalsingCollector;
import com.android.systemui.flags.FeatureFlags;
import com.android.systemui.res.R;
import com.android.systemui.user.domain.interactor.SelectedUserInteractor;

import java.util.HashMap;
import java.util.Map;

public abstract class KeyguardAbsKeyInputViewController<T extends KeyguardAbsKeyInputView>
        extends KeyguardInputViewController<T> {
    private final KeyguardUpdateMonitor mKeyguardUpdateMonitor;
    protected final LockPatternUtils mLockPatternUtils;
    private final LatencyTracker mLatencyTracker;
    private final FalsingCollector mFalsingCollector;
    private final EmergencyButtonController mEmergencyButtonController;
    private CountDownTimer mCountdownTimer;
    private boolean mDismissing;
    protected AsyncTask<?, ?, ?> mPendingLockCheck;
    protected boolean mResumed;
    protected boolean mLockedOut;
    // True if a primary credential is being entered, false if it is a biometric second factor.
    private boolean mPrimary;

    private final KeyDownListener mKeyDownListener = (keyCode, keyEvent) -> {
        // Fingerprint sensor sends a KeyEvent.KEYCODE_UNKNOWN.
        // We don't want to consider it valid user input because the UI
        // will already respond to the event.
        if (keyCode != KeyEvent.KEYCODE_UNKNOWN) {
            onUserInput();
        }
        return false;
    };

    private final EmergencyButtonCallback mEmergencyButtonCallback = new EmergencyButtonCallback() {
        @Override
        public void onEmergencyButtonClickedWhenInCall() {
            getKeyguardSecurityCallback().reset();
        }
    };

    protected KeyguardAbsKeyInputViewController(T view,
            KeyguardUpdateMonitor keyguardUpdateMonitor,
            SecurityMode securityMode,
            LockPatternUtils lockPatternUtils,
            KeyguardSecurityCallback keyguardSecurityCallback,
            KeyguardMessageAreaController.Factory messageAreaControllerFactory,
            LatencyTracker latencyTracker, FalsingCollector falsingCollector,
            EmergencyButtonController emergencyButtonController,
            FeatureFlags featureFlags, SelectedUserInteractor selectedUserInteractor) {
        super(view, securityMode, keyguardSecurityCallback, emergencyButtonController,
                messageAreaControllerFactory, featureFlags, selectedUserInteractor);
        mKeyguardUpdateMonitor = keyguardUpdateMonitor;
        mLockPatternUtils = lockPatternUtils;
        mLatencyTracker = latencyTracker;
        mFalsingCollector = falsingCollector;

        final int userId = mSelectedUserInteractor.getSelectedUserId();
        mEmergencyButtonController = emergencyButtonController;
        // TODO: It doesn't matter because this will be removed, but I believe the value of user
        //  can change, so this would not be valid. If we end up keeping it, move to a method
        //  getPrimary() and use that everywhere instead.
        if (mKeyguardUpdateMonitor.getUserAuthenticatedWithFingerprint(userId) &&
                mKeyguardUpdateMonitor.getBiometricSecondFactorEnabled(userId)) {
            mPrimary = false;
        } else {
            mPrimary = true;
        }
    }

    abstract void resetState();

    @Override
    public void onInit() {
        super.onInit();
    }

    @Override
    protected void onViewAttached() {
        super.onViewAttached();
        mView.setKeyDownListener(mKeyDownListener);
        mEmergencyButtonController.setEmergencyButtonCallback(mEmergencyButtonCallback);
        // if the user is currently locked out, enforce it.
        long deadline = mLockPatternUtils.getLockoutAttemptDeadline(
                mSelectedUserInteractor.getSelectedUserId(), mPrimary);
        if (shouldLockout(deadline)) {
            handleAttemptLockout(deadline);
        }
    }

    @Override
    public void reset() {
        super.reset();
        // start fresh
        mDismissing = false;
        mView.resetPasswordText(false /* animate */, false /* announce */);
        resetState();
    }

    @Override
    public boolean needsInput() {
        return false;
    }

    @Override
    public void showMessage(CharSequence message, ColorStateList colorState, boolean animated) {
        if (mMessageAreaController == null) {
            return;
        }

        if (colorState != null) {
            mMessageAreaController.setNextMessageColor(colorState);
        }
        mMessageAreaController.setMessage(message, animated);
    }

    // Allow subclasses to override this behavior
    protected boolean shouldLockout(long deadline) {
        return deadline != 0;
    }

    // Prevent user from using the PIN/Password entry until scheduled deadline.
    protected void handleAttemptLockout(long elapsedRealtimeDeadline) {
        mView.setPasswordEntryEnabled(false);
        mView.setPasswordEntryInputEnabled(false);
        mLockedOut = true;
        long elapsedRealtime = SystemClock.elapsedRealtime();
        long secondsInFuture = (long) Math.ceil(
                (elapsedRealtimeDeadline - elapsedRealtime) / 1000.0);
        getKeyguardSecurityCallback().onAttemptLockoutStart(secondsInFuture);
        mCountdownTimer = new CountDownTimer(secondsInFuture * 1000, 1000) {

            @Override
            public void onTick(long millisUntilFinished) {
                int secondsRemaining = (int) Math.round(millisUntilFinished / 1000.0);
                Map<String, Object> arguments = new HashMap<>();
                arguments.put("count", secondsRemaining);
                mMessageAreaController.setMessage(
                        PluralsMessageFormatter.format(
                            mView.getResources(),
                            arguments,
                            R.string.kg_too_many_failed_attempts_countdown),
                        /* animate= */ false);
            }

            @Override
            public void onFinish() {
                mMessageAreaController.setMessage("");
                mLockedOut = false;
                resetState();
            }
        }.start();
    }

    void onPasswordChecked(int userId, boolean matched, int timeoutMs, boolean isValidPassword) {
        boolean dismissKeyguard = mSelectedUserInteractor.getSelectedUserId() == userId;
        if (matched) {
            getKeyguardSecurityCallback().reportUnlockAttempt(userId, mPrimary, true, 0);
            if (!mPrimary) {
                mKeyguardUpdateMonitor.addPendingBiometricSecondFactorAuthTokenToKeyStore(userId);
            }
            if (dismissKeyguard) {
                mDismissing = true;
                mLatencyTracker.onActionStart(LatencyTracker.ACTION_LOCKSCREEN_UNLOCK);
                getKeyguardSecurityCallback().dismiss(true, userId, getSecurityMode());
            }
        } else {
            mView.resetPasswordText(true /* animate */, false /* announce deletion if no match */);
            if (isValidPassword) {
                getKeyguardSecurityCallback().reportUnlockAttempt(userId, mPrimary,
                        false, timeoutMs);
                if (timeoutMs > 0) {
                    long deadline = mLockPatternUtils.setLockoutAttemptDeadline(
                            userId, mPrimary, timeoutMs);
                    handleAttemptLockout(deadline);

                    // This is working but broken. No point making it better because this will all
                    // be moved to separate controller soon.
                    if (!mPrimary) {
                        // If primary is PIN too we will keep this controller so need to cancel
                        // countdown.
                        mCountdownTimer.cancel();
                        mPrimary = true;
                        resetState();

                        // onDevicePolicyManagerStateChanged() calls showPrimarySecurityScreen.
                        // This doesn't matter but could look into what causes it. Maybe it is
                        // called on every failed attempt as policy is saved?

                        mKeyguardUpdateMonitor.clearFingerprintRecognized(userId);
                        // Not sure about this.
                        mDismissing = false;
                        // I don't think this is strictly needed because same call is made by
                        // onDevicePolicyManagerStateChanged(), but it can't hurt and makes code
                        // more explicit and robust.
                        getKeyguardSecurityCallback().showCurrentSecurityScreen();
                    }
                }
            }
            if (timeoutMs == 0) {
                mMessageAreaController.setMessage(mView.getWrongPasswordStringId());
            }
            startErrorAnimation();
        }
    }

    protected void startErrorAnimation() { /* no-op */ }

    protected void verifyPasswordAndUnlock() {
        if (mDismissing) return; // already verified but haven't been dismissed; don't do it again.
        if (mLockedOut) return;

        final LockscreenCredential password = mView.getEnteredCredential();
        mView.setPasswordEntryInputEnabled(false);
        if (mPendingLockCheck != null) {
            mPendingLockCheck.cancel(false);
        }

        final int userId = mSelectedUserInteractor.getSelectedUserId();
        if (!mPrimary) {
            password.setPrimaryCredential(false);
        }

        if (password.size() <= MINIMUM_PASSWORD_LENGTH_BEFORE_REPORT) {
            // to avoid accidental lockout, only count attempts that are long enough to be a
            // real password. This may require some tweaking.
            mView.setPasswordEntryInputEnabled(true);
            onPasswordChecked(userId, false /* matched */, 0, false /* not valid - too short */);
            password.zeroize();
            return;
        }

        mLatencyTracker.onActionStart(ACTION_CHECK_CREDENTIAL);
        mLatencyTracker.onActionStart(ACTION_CHECK_CREDENTIAL_UNLOCKED);

        // TODO: ?
        mKeyguardUpdateMonitor.setCredentialAttempted();
        mPendingLockCheck = LockPatternChecker.checkCredential(
                mLockPatternUtils,
                password,
                userId,
                new LockPatternChecker.OnCheckCallback() {

                    @Override
                    public void onEarlyMatched() {
                        mLatencyTracker.onActionEnd(ACTION_CHECK_CREDENTIAL);

                        onPasswordChecked(userId, true /* matched */, 0 /* timeoutMs */,
                                true /* isValidPassword */);
                        password.zeroize();
                    }

                    @Override
                    public void onChecked(boolean matched, int timeoutMs) {
                        mLatencyTracker.onActionEnd(ACTION_CHECK_CREDENTIAL_UNLOCKED);
                        mView.setPasswordEntryInputEnabled(true);
                        mPendingLockCheck = null;
                        if (!matched) {
                            onPasswordChecked(userId, false /* matched */, timeoutMs,
                                    true /* isValidPassword */);
                        }
                        password.zeroize();
                    }

                    @Override
                    public void onCancelled() {
                        // We already got dismissed with the early matched callback, so we cancelled
                        // the check. However, we still need to note down the latency.
                        mLatencyTracker.onActionEnd(ACTION_CHECK_CREDENTIAL_UNLOCKED);
                        password.zeroize();
                    }
                });
    }

    @Override
    public void showPromptReason(int reason) {
        if (reason != PROMPT_REASON_NONE) {
            int promtReasonStringRes = mView.getPromptReasonStringRes(reason);
            if (promtReasonStringRes != 0) {
                mMessageAreaController.setMessage(
                        mView.getResources().getString(promtReasonStringRes), false);
            }
        }
    }

    protected void onUserInput() {
        mFalsingCollector.updateFalseConfidence(FalsingClassifier.Result.passed(0.6));
        getKeyguardSecurityCallback().userActivity();
        getKeyguardSecurityCallback().onUserInput();
        mMessageAreaController.setMessage("");
    }

    @Override
    public void onResume(int reason) {
        mResumed = true;
    }

    @Override
    public void onPause() {
        mResumed = false;

        if (mCountdownTimer != null) {
            mCountdownTimer.cancel();
            mCountdownTimer = null;
        }
        if (mPendingLockCheck != null) {
            mPendingLockCheck.cancel(false);
            mPendingLockCheck = null;
        }
        reset();
    }
}
