package com.juanma0511.rootdetector.zygote;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;

public final class DirtySepolicyService extends Service {

    private final IDirtySepolicyService.Stub binder = new IDirtySepolicyService.Stub() {
        @Override
        public String getResult() {
            return AppZygote.result;
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return Process.isIsolated() ? binder : null;
    }
}
