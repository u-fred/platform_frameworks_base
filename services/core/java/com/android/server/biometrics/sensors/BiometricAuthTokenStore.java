package com.android.server.biometrics.sensors;

import android.annotation.NonNull;
import android.security.KeyStore;
import android.util.Slog;
import android.util.SparseArray;

public class BiometricAuthTokenStore {
    private static final String TAG = "BiometricAuthTokenStore";
    // Technically this does not need to be an array because managed profiles will never have a
    // pending auth token and the value will be cleared when switching between full user types.
    @NonNull
    private final SparseArray<byte[]> mPendingSecondFactorAuthTokens;

    public BiometricAuthTokenStore() {
        mPendingSecondFactorAuthTokens = new SparseArray<>();
    }

    public void storePendingSecondFactorAuthToken(int userId, byte[] token) {
        synchronized (mPendingSecondFactorAuthTokens) {
            mPendingSecondFactorAuthTokens.put(userId, token);
        }
    }

    public void addPendingAuthTokenToKeyStore(int userId) {
        synchronized (mPendingSecondFactorAuthTokens) {
            byte[] authToken = mPendingSecondFactorAuthTokens.get(userId);
            if (authToken != null) {
                final int result = KeyStore.getInstance().addAuthToken(authToken);
                if (result != 0 /* success */) {
                    Slog.d(TAG, "Error adding auth token : " + result);
                } else {
                    Slog.d(TAG, "addAuthToken: " + result);
                }
            }

            // TODO: zero/gc?
            mPendingSecondFactorAuthTokens.remove(userId);
        }
    }

    public void clearPendingAuthTokens() {
        synchronized (mPendingSecondFactorAuthTokens) {
            mPendingSecondFactorAuthTokens.clear();
        }
    }
}
