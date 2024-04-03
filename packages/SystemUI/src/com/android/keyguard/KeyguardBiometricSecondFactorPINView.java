package com.android.keyguard;

import android.content.Context;
import android.util.AttributeSet;

import com.android.internal.widget.LockscreenCredential;


/**
 * Displays a PIN pad for biometric second factor unlock.
 */
public class KeyguardBiometricSecondFactorPINView extends KeyguardPINView {


    public KeyguardBiometricSecondFactorPINView(Context context) {
        super(context);
    }

    public KeyguardBiometricSecondFactorPINView(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    @Override
    protected LockscreenCredential getEnteredCredential() {
        return LockscreenCredential.createPinOrNone(mPasswordEntry.getText(), false);
    }

}
