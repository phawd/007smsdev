package com.smstest.app.core

import android.util.Log
import com.smstest.app.BuildConfig

/**
 * Conditional logging utility that only logs in debug builds
 * This prevents sensitive information from being logged in production
 */
object Logger {
    
    fun d(tag: String, message: String) {
        if (BuildConfig.DEBUG) {
            Log.d(tag, message)
        }
    }
    
    fun v(tag: String, message: String) {
        if (BuildConfig.DEBUG) {
            Log.v(tag, message)
        }
    }
    
    fun i(tag: String, message: String) {
        Log.i(tag, message)  // Info logs are kept in production
    }
    
    fun w(tag: String, message: String) {
        Log.w(tag, message)  // Warning logs are kept in production
    }
    
    fun w(tag: String, message: String, throwable: Throwable) {
        Log.w(tag, message, throwable)
    }
    
    fun e(tag: String, message: String) {
        Log.e(tag, message)  // Error logs are kept in production
    }
    
    fun e(tag: String, message: String, throwable: Throwable) {
        Log.e(tag, message, throwable)
    }
}