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

    /** Both app_zygote probe results fetched from a single service bind. */
    private data class ZygoteResults(val sepolicy: String, val contextValidity: String)

    @Volatile private var cached: ZygoteResults? = null

    /** DirtySepolicy sweep result (see AppZygote.result). */
    fun query(context: Context, timeoutMs: Long = 4000L): String =
        obtain(context, timeoutMs).sepolicy

    /** SELinux context-validity oracle result (see AppZygote.oracleResult). */
    fun queryContextValidity(context: Context, timeoutMs: Long = 4000L): String =
        obtain(context, timeoutMs).contextValidity

    private fun obtain(context: Context, timeoutMs: Long): ZygoteResults {
        cached?.let { return it }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            val err = "ERROR: app_zygote unsupported on API ${Build.VERSION.SDK_INT}"
            return ZygoteResults(err, err).also { cached = it }
        }
        val resultRef = AtomicReference<ZygoteResults?>(null)
        val latch = CountDownLatch(1)
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                try {
                    val stub = IDirtySepolicyService.Stub.asInterface(service)
                    resultRef.set(
                        ZygoteResults(
                            stub.result ?: "ERROR: null result from service",
                            stub.contextValidityResult ?: "ERROR: null oracle result from service"
                        )
                    )
                } catch (t: Throwable) {
                    val err = "ERROR: ${t.javaClass.simpleName}: ${t.message}"
                    resultRef.set(ZygoteResults(err, err))
                } finally {
                    latch.countDown()
                }
            }
            override fun onServiceDisconnected(name: ComponentName) {}
            override fun onBindingDied(name: ComponentName) {
                resultRef.compareAndSet(null, err("service binding died"))
                latch.countDown()
            }
            override fun onNullBinding(name: ComponentName) {
                resultRef.compareAndSet(null, err("null binding from service"))
                latch.countDown()
            }
        }
        val appCtx = context.applicationContext
        val intent = Intent(appCtx, DirtySepolicyService::class.java)
        // CRITICAL: use bindIsolatedService (API 29+) with an instance name so
        // the system actually routes the isolated process through app_zygote
        // (per useAppZygote="true" + zygotePreloadName in the manifest).
        // Plain bindService() can spawn a regular isolated process that
        // bypasses app_zygote entirely -- in that case AppZygote.doPreload()
        // is never called and the results stay at their initial sentinel
        // "ERROR: app zygote not called", which is what we observed on the
        // user's rooted device.
        val bound = try {
            appCtx.bindIsolatedService(
                intent,
                Context.BIND_AUTO_CREATE,
                "dirtysepolicy",
                appCtx.mainExecutor,
                conn
            )
        } catch (_: Throwable) {
            false
        }
        if (!bound) {
            return err("failed to bind isolated service").also { cached = it }
        }
        try {
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                // Per LSPosed README, timeout MAY indicate app_zygote was killed
                // by a root framework. In practice it also fires on slow boot,
                // restricted background bind, and benign system pressure --
                // so we surface it as ERROR (informational), not a detection.
                resultRef.compareAndSet(null, err("service connection timed out"))
            }
        } finally {
            try { context.applicationContext.unbindService(conn) } catch (_: Throwable) {}
        }
        return (resultRef.get() ?: err("unknown bind state")).also { cached = it }
    }

    private fun err(message: String): ZygoteResults =
        ZygoteResults("ERROR: $message", "ERROR: $message")

    fun reset() {
        cached = null
    }
}
