package com.github.shadowsocks.plugin.v2ray

import android.content.Context
import androidx.core.content.edit
import com.github.shadowsocks.plugin.PluginOptions

import androidx.preference.PreferenceManager

object Settings {
    fun getOptions(context: Context): PluginOptions {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        val options = PluginOptions()
        prefs.all.forEach { (key, value) ->
            if (value is String) options.put(key, value)
        }
        return options
    }

    fun saveOptions(context: Context, options: PluginOptions) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        prefs.edit {
            options.forEach { (key, value) ->
                putString(key, value)
            }
        }
    }
}
