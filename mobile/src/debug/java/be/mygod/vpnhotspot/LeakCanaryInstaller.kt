package be.mygod.vpnhotspot

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Handler
import android.os.Looper
//import com.google.firebase.crashlytics.CustomKeysAndValues
//import com.google.firebase.crashlytics.FirebaseCrashlytics
import leakcanary.EventListener
import leakcanary.LeakCanary
import shark.Leak

class LeakCanaryInstaller : ContentProvider() {
    override fun onCreate(): Boolean {
        Handler(Looper.getMainLooper()).post {
            val config = LeakCanary.config
            LeakCanary.config = config.copy(eventListeners = config.eventListeners + EventListener { event ->
                when (event) {
                    is EventListener.Event.HeapAnalysisDone.HeapAnalysisSucceeded -> {
                        val heapAnalysis = event.heapAnalysis
                        val appLeaks: List<Leak> = heapAnalysis.applicationLeaks
                        val libLeaks: List<Leak> = heapAnalysis.libraryLeaks
                        for ((type, leaks) in sequenceOf("application" to appLeaks, "library" to libLeaks)) {
                            for (leak in leaks) {
                                val firstTrace = leak.leakTraces.firstOrNull()
                                val traceSummary = firstTrace?.let { trace ->
                                    "${trace.gcRootType.name}: ${
                                        (trace.referencePath.asSequence().map { reference ->
                                            "${reference.originObject.classSimpleName}.${reference.referenceDisplayName}"
                                        } + sequenceOf(trace.leakingObject.classSimpleName)).joinToString(" -> ")
                                    }".take(1024)
                                }
                                val exception = IllegalStateException(
                                    "LeakCanary $type leak: ${leak.shortDescription}" +
                                            traceSummary?.let { ": $it" }.orEmpty() +
                                            " [${leak.signature}]")
                                exception.stackTrace = arrayOf(StackTraceElement("LeakCanary", "${type}Leak",
                                    leak.signature.take(255), 1))
                            }
                        }
                    }

                    is EventListener.Event.HeapAnalysisDone.HeapAnalysisFailed -> {
                        val heapAnalysis = event.heapAnalysis

                    }

                    else -> Unit
                }
            })
        }
        return true
    }

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = 0
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) = 0
}
