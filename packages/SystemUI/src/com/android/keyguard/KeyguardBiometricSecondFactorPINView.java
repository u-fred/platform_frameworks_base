package com.android.keyguard;

import android.content.Context;
import android.util.AttributeSet;

import com.android.systemui.res.R;

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
    public int getWrongPasswordStringId() {
        return R.string.kg_wrong_biometric_second_factor_pin;
    }
}
