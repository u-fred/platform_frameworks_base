package com.android.keyguard;

import com.android.internal.logging.UiEventLogger;
import com.android.internal.util.LatencyTracker;
import com.android.internal.widget.LockPatternUtils;
import com.android.systemui.classifier.FalsingCollector;
import com.android.systemui.flags.FeatureFlags;
import com.android.systemui.res.R;
import com.android.systemui.statusbar.policy.DevicePostureController;
import com.android.systemui.user.domain.interactor.SelectedUserInteractor;

public class KeyguardBiometricSecondFactorPinViewController extends KeyguardPinViewController {

    protected KeyguardBiometricSecondFactorPinViewController(KeyguardBiometricSecondFactorPINView
            view, KeyguardUpdateMonitor keyguardUpdateMonitor,
            KeyguardSecurityModel.SecurityMode securityMode, LockPatternUtils lockPatternUtils,
            KeyguardSecurityCallback keyguardSecurityCallback,
            KeyguardMessageAreaController.Factory messageAreaControllerFactory,
            LatencyTracker latencyTracker, LiftToActivateListener liftToActivateListener,
            EmergencyButtonController emergencyButtonController, FalsingCollector falsingCollector,
            DevicePostureController postureController, FeatureFlags featureFlags,
            SelectedUserInteractor selectedUserInteractor, UiEventLogger uiEventLogger) {
        super(view, keyguardUpdateMonitor, securityMode, lockPatternUtils, keyguardSecurityCallback,
                messageAreaControllerFactory, latencyTracker, liftToActivateListener,
                emergencyButtonController, falsingCollector, postureController, featureFlags,
                selectedUserInteractor, uiEventLogger);
        // TODO: Biometric second factor.
        //mPinLength = mLockPatternUtils.getPinLength(selectedUserInteractor.getSelectedUserId());
    }

    @Override
    protected int getInitialMessageResId() {
        return R.string.keyguard_enter_your_biometric_second_factor_pin;
    }

    @Override
    protected long getDeadline() {
        return mLockPatternUtils.getLockoutAttemptDeadline(
                mSelectedUserInteractor.getSelectedUserId(), false);
    }

    @Override
    protected boolean shouldDisableAutoConfirmation() {
        return mLockPatternUtils.getCurrentFailedBiometricSecondFactorAttempts(
                mSelectedUserInteractor.getSelectedUserId()) >= MIN_FAILED_PIN_ATTEMPTS;
    }

    void onPasswordChecked(int userId, boolean matched, int timeoutMs, boolean isValidPassword) {
        boolean dismissKeyguard = mSelectedUserInteractor.getSelectedUserId() == userId;
        if (matched) {
            mKeyguardUpdateMonitor.addPendingBiometricSecondFactorAuthTokenToKeyStore(userId);
            getKeyguardSecurityCallback().reportBiometricSecondFactorUnlockAttempt(userId, true,
                    0);
            if (dismissKeyguard) {
                mDismissing = true;
                mLatencyTracker.onActionStart(LatencyTracker.ACTION_LOCKSCREEN_UNLOCK);
                getKeyguardSecurityCallback().dismiss(true, userId, getSecurityMode());
            }
        } else {
            mView.resetPasswordText(true /* animate */, false /* announce deletion if no match */);
            if (isValidPassword) {
                getKeyguardSecurityCallback().reportBiometricSecondFactorUnlockAttempt(userId,
                        false, timeoutMs);
                if (timeoutMs > 0) {
                    long deadline = mLockPatternUtils.setLockoutAttemptDeadline(
                            userId, false, timeoutMs);
                    handleAttemptLockout(deadline);
                }
            }
            if (timeoutMs == 0) {
                mMessageAreaController.setMessage(mView.getWrongPasswordStringId());
            }
            startErrorAnimation();
        }
    }
}
