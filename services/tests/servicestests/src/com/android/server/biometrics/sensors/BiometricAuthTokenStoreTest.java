/*
 * Copyright (C) 2023 The Android Open Source Project
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

package com.android.server.biometrics.sensors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import android.security.KeyStore;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class BiometricAuthTokenStoreTest {
    @Rule
    public final MockitoRule mockito = MockitoJUnit.rule();

    @Mock
    private KeyStore mKeyStore;

    private BiometricAuthTokenStore mBiometricAuthTokenStore;
    private int mUserId;
    private byte[] mAuthToken;

    @Before
    public void setUp() {
        mUserId = 0;
        mAuthToken =  "Mock Auth Token".getBytes();
        mBiometricAuthTokenStore = new BiometricAuthTokenStore(mKeyStore);
    }

    @Test
    public void storePendingAuthToken_OnSuccess_StoresToken() {
        assertNull(mBiometricAuthTokenStore.getPendingAuthToken(mUserId));
        mBiometricAuthTokenStore.storePendingAuthToken(mUserId, mAuthToken);
        assertEquals(mAuthToken, mBiometricAuthTokenStore.getPendingAuthToken(mUserId));
    }

    @Test
    public void addPendingAuthTokenToKeyStore_WithPendingAuthToken_AddsTokenToKeyStore() {
        mBiometricAuthTokenStore.storePendingAuthToken(mUserId, mAuthToken);

        // Return success.
        when(mKeyStore.addAuthToken(mAuthToken)).thenReturn(0);

        assertTrue(mBiometricAuthTokenStore.addPendingAuthTokenToKeyStore(mUserId));

        // Verify token removed from pending store.
        assertNull(mBiometricAuthTokenStore.getPendingAuthToken(mUserId));
    }

    @Test
    public void addPendingAuthTokenToKeyStore_WithInvalidPendingAuthToken_ReturnsFalse() {
        mBiometricAuthTokenStore.storePendingAuthToken(mUserId, mAuthToken);

        // Return not success.
        when(mKeyStore.addAuthToken(mAuthToken)).thenReturn(1);

        assertFalse(mBiometricAuthTokenStore.addPendingAuthTokenToKeyStore(mUserId));

        // Verify token removed from pending store.
        assertNull(mBiometricAuthTokenStore.getPendingAuthToken(mUserId));
    }

    @Test
    public void addPendingAuthTokenToKeyStore_WithoutPendingAuthToken_ReturnsFalse() {
        // Verify no token in store.
        assertNull(mBiometricAuthTokenStore.getPendingAuthToken(mUserId));

        assertFalse(mBiometricAuthTokenStore.addPendingAuthTokenToKeyStore(mUserId));
    }

    @Test
    public void clearPendingAuthTokens_Success_ClearsTokens() {
        mBiometricAuthTokenStore.storePendingAuthToken(mUserId, mAuthToken);

        mBiometricAuthTokenStore.clearPendingAuthTokens();

        assertNull(mBiometricAuthTokenStore.getPendingAuthToken(mUserId));
    }
}
