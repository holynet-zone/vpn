package dev.holynet.gui;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.view.Display;
import android.view.HapticFeedbackConstants;
import android.view.View;
import android.view.Window;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import java.util.HashSet;
import java.util.List;


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

    public static void hapticDetent(final Activity activity) {
        if (activity == null) {
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Window w = activity.getWindow();
                View v = (w != null) ? w.getDecorView() : null;
                if (v == null) {
                    return;
                }
                int flags = HapticFeedbackConstants.FLAG_IGNORE_VIEW_SETTING
                          | HapticFeedbackConstants.FLAG_IGNORE_GLOBAL_SETTING;
                int effect = (Build.VERSION.SDK_INT >= 30)
                        ? HapticFeedbackConstants.CONFIRM
                        : HapticFeedbackConstants.LONG_PRESS;
                v.performHapticFeedback(effect, flags);
            }
        });
    }

    public static String listApps(final Activity activity) {
        if (activity == null) {
            return "";
        }
        try {
            PackageManager pm = activity.getPackageManager();
            Intent main = new Intent(Intent.ACTION_MAIN, null);
            main.addCategory(Intent.CATEGORY_LAUNCHER);
            List<ResolveInfo> ris = pm.queryIntentActivities(main, 0);
            StringBuilder sb = new StringBuilder();
            HashSet<String> seen = new HashSet<String>();
            String self = activity.getPackageName();
            for (ResolveInfo ri : ris) {
                if (ri.activityInfo == null) {
                    continue;
                }
                ApplicationInfo ai = ri.activityInfo.applicationInfo;
                if (ai == null || ai.packageName == null) {
                    continue;
                }
                String pkg = ai.packageName;
                if (pkg.equals(self) || !seen.add(pkg)) {
                    continue;
                }
                String label = String.valueOf(ri.loadLabel(pm));
                boolean sys = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                        && (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0;
                String cat = "";
                if (Build.VERSION.SDK_INT >= 26) {
                    CharSequence ct = ApplicationInfo.getCategoryTitle(activity, ai.category);
                    if (ct != null) {
                        cat = ct.toString();
                    }
                }
                label = label.replace('\t', ' ').replace('\n', ' ').trim();
                cat = cat.replace('\t', ' ').replace('\n', ' ').trim();
                sb.append(pkg).append('\t').append(label).append('\t')
                  .append(cat).append('\t').append(sys ? '1' : '0').append('\n');
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    public static byte[] appIcons(final Activity activity, final String pkgsJoined, final int size) {
        if (activity == null || pkgsJoined == null || size <= 0) {
            return new byte[0];
        }
        try {
            PackageManager pm = activity.getPackageManager();
            String[] pkgs = pkgsJoined.split("\t", -1);
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            int[] px = new int[size * size];
            byte[] header = new byte[4];
            for (String pkg : pkgs) {
                byte[] rgba = null;
                try {
                    Drawable d = pm.getApplicationIcon(pkg);
                    Bitmap bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888);
                    Canvas canvas = new Canvas(bmp);
                    d.setBounds(0, 0, size, size);
                    d.draw(canvas);
                    bmp.getPixels(px, 0, size, 0, 0, size, size);
                    bmp.recycle();
                    rgba = new byte[size * size * 4];
                    for (int i = 0; i < px.length; i++) {
                        int p = px[i];
                        int o = i * 4;
                        rgba[o] = (byte) ((p >> 16) & 0xff);
                        rgba[o + 1] = (byte) ((p >> 8) & 0xff);
                        rgba[o + 2] = (byte) (p & 0xff);
                        rgba[o + 3] = (byte) ((p >> 24) & 0xff);
                    }
                } catch (Exception e) {
                    rgba = null;
                }
                int len = (rgba == null) ? 0 : rgba.length;
                header[0] = (byte) ((len >> 24) & 0xff);
                header[1] = (byte) ((len >> 16) & 0xff);
                header[2] = (byte) ((len >> 8) & 0xff);
                header[3] = (byte) (len & 0xff);
                bos.write(header, 0, 4);
                if (rgba != null) {
                    bos.write(rgba, 0, rgba.length);
                }
            }
            return bos.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    public static void openUrl(final Activity activity, final String url) {
        if (activity == null || url == null) {
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                try {
                    Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
                    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    activity.startActivity(i);
                } catch (Exception e) {
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
