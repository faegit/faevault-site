package com.vault.ui.screens

import org.junit.Assert.*
import org.junit.Test

class PhotoPresentationTest {
    @Test fun disablingPhotoBlurCannotBypassSecondaryProtection() {
        assertEquals(PhotoPresentation(true, true), photoPresentation(true, false, false))
        assertEquals(PhotoPresentation(false, false), photoPresentation(true, true, false))
    }
    @Test fun alwaysBlurPersistsAfterVerificationWithoutLockingViewer() {
        assertEquals(PhotoPresentation(false, true), photoPresentation(true, true, true))
        assertEquals(PhotoPresentation(false, true), photoPresentation(false, false, true))
        assertEquals(PhotoPresentation(false, false), photoPresentation(false, false, false))
    }
}
