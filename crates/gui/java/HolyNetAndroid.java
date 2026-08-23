package dev.holynet.gui;

import android.app.Activity;
import android.os.Build;
import android.view.Display;
import android.view.View;
import android.view.Window;
import android.view.WindowInsetsController;
import android.view.WindowManager;


public final class HolyNetAndroid {
    public static void setLightSystemBars(final Activity activity, final boolean light) {
        if (activity == null) {
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Window w = activity.getWindow();
                if (w == null) {
                    return;
                }
                if (Build.VERSION.SDK_INT >= 30) {
                    WindowInsetsController c = w.getInsetsController();
                    if (c != null) {
                        int mask = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                                 | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
                        c.setSystemBarsAppearance(light ? mask : 0, mask);
                    }
                } else if (Build.VERSION.SDK_INT >= 23) {
                    View decor = w.getDecorView();
                    int flags = decor.getSystemUiVisibility();
                    int statusFlag = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
                    int navFlag = (Build.VERSION.SDK_INT >= 26)
                            ? View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR : 0;
                    if (light) {
                        flags |= statusFlag | navFlag;
                    } else {
                        flags &= ~(statusFlag | navFlag);
                    }
                    decor.setSystemUiVisibility(flags);
                }
            }
        });
    }

    public static void requestHighRefreshRate(final Activity activity) {
        if (activity == null) {
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Window w = activity.getWindow();
                if (w == null) {
                    return;
                }
                Display display = (Build.VERSION.SDK_INT >= 30)
                        ? activity.getDisplay()
                        : activity.getWindowManager().getDefaultDisplay();
                if (display == null) {
                    return;
                }
                Display.Mode current = display.getMode();
                Display.Mode[] modes = display.getSupportedModes();
                int bestId = 0;
                float bestRate = current.getRefreshRate();
                for (Display.Mode m : modes) {
                    if (m.getPhysicalWidth() == current.getPhysicalWidth()
                            && m.getPhysicalHeight() == current.getPhysicalHeight()
                            && m.getRefreshRate() > bestRate + 0.1f) {
                        bestRate = m.getRefreshRate();
                        bestId = m.getModeId();
                    }
                }
                if (bestId != 0) {
                    WindowManager.LayoutParams lp = w.getAttributes();
                    lp.preferredDisplayModeId = bestId;
                    w.setAttributes(lp);
                }
            }
        });
    }
}
