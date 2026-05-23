package com.juanma0511.rootdetector.zygote

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.IBinder
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

object DirtySepolicyClient {

    @Volatile private var cached: String? = null

    fun query(context: Context, timeoutMs: Long = 4000L): String {
        cached?.let { return it }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            cached = "ERROR: app_zygote unsupported on API ${Build.VERSION.SDK_INT}"
            return cached!!
        }
        val resultRef = AtomicReference<String?>(null)
        val latch = CountDownLatch(1)
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                try {
                    resultRef.set(
                        IDirtySepolicyService.Stub.asInterface(service).result
                            ?: "ERROR: null result from service"
                    )
                } catch (t: Throwable) {
                    resultRef.set("ERROR: ${t.javaClass.simpleName}: ${t.message}")
                } finally {
                    latch.countDown()
                }
            }
            override fun onServiceDisconnected(name: ComponentName) {}
            override fun onBindingDied(name: ComponentName) {
                resultRef.compareAndSet(null, "ERROR: service binding died")
                latch.countDown()
            }
            override fun onNullBinding(name: ComponentName) {
                resultRef.compareAndSet(null, "ERROR: null binding from service")
                latch.countDown()
            }
        }
        val intent = Intent(context, DirtySepolicyService::class.java)
        val bound = try {
            context.applicationContext.bindService(intent, conn, Context.BIND_AUTO_CREATE)
        } catch (_: Throwable) {
            false
        }
        if (!bound) {
            cached = "ERROR: failed to bind isolated service"
            return cached!!
        }
        try {
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                // Per LSPosed README, timeout MAY indicate app_zygote was killed
                // by a root framework. In practice it also fires on slow boot,
                // restricted background bind, and benign system pressure --
                // so we surface it as ERROR (informational), not a detection.
                resultRef.compareAndSet(null, "ERROR: service connection timed out")
            }
        } finally {
            try { context.applicationContext.unbindService(conn) } catch (_: Throwable) {}
        }
        cached = resultRef.get() ?: "ERROR: unknown bind state"
        return cached!!
    }

    fun reset() {
        cached = null
    }
}
