/*******************************************************************************
 *                                                                             *
 *  Copyright (C) 2019 by Max Lv <max.c.lv@gmail.com>                          *
 *  Copyright (C) 2019 by Mygod Studio <contact-shadowsocks-android@mygod.be>  *
 *                                                                             *
 *  This program is free software: you can redistribute it and/or modify       *
 *  it under the terms of the GNU General Public License as published by       *
 *  the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                        *
 *                                                                             *
 *  This program is distributed in the hope that it will be useful,            *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 *  GNU General Public License for more details.                               *
 *                                                                             *
 *  You should have received a copy of the GNU General Public License          *
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                             *
 *******************************************************************************/

package com.github.shadowsocks.plugin.v2ray

import android.os.Bundle
import android.text.InputType
import android.view.View
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.preference.EditTextPreference
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreferenceCompat
import com.github.shadowsocks.plugin.PluginOptions

class ConfigFragment : PreferenceFragmentCompat(), Preference.OnPreferenceChangeListener {
    private val serverAddress by lazy { findPreference<EditTextPreference>("server_address")!! }
    private val serverPort by lazy { findPreference<EditTextPreference>("server_port")!! }
    private val password by lazy { findPreference<EditTextPreference>("password")!! }
    private val encryptMethod by lazy { findPreference<ListPreference>("encrypt_method")!! }
    private val modePref by lazy { findPreference<Preference>("mode")!! }
    private val host by lazy { findPreference<EditTextPreference>("host")!! }
    private val loglevel by lazy { findPreference<ListPreference>("loglevel")!! }
    private val upstreamSocks by lazy { findPreference<EditTextPreference>("upstreamSocks")!! }
    private val ipv6Support by lazy { findPreference<SwitchPreferenceCompat>("ipv6_support")!! }

    private fun readMode() = Pair("grpc", true)

    val options get() = PluginOptions().apply {
        put("server_address", serverAddress.text ?: "qtopie.space")
        put("server_port", serverPort.text ?: "")
        put("password", password.text ?: "")
        put("encrypt_method", encryptMethod.value ?: "xchacha20-ietf-poly1305")
        
        val (mode, tls) = readMode()
        putWithDefault("mode", mode)
        if (tls) this["tls"] = null
        putWithDefault("host", host.text, "qtopie.space")
        putWithDefault("loglevel", loglevel.value, "warning")
        putWithDefault("upstreamSocks", upstreamSocks.text, "")
        putWithDefault("ipv6_support", ipv6Support.isChecked.toString(), "false")
    }

    fun onInitializePluginOptions(options: PluginOptions) {
        serverAddress.text = options["server_address"] ?: "qtopie.space"
        serverPort.text = options["server_port"] ?: "443"
        password.text = options["password"] ?: "flywater_3kchi"
        password.summary = "********"
        encryptMethod.value = options["encrypt_method"] ?: "xchacha20-ietf-poly1305"
        
        // UI is fixed to gRPC with TLS enforced
        modePref.summary = "gRPC (TLS enforced)"
        host.text = options["host"] ?: "qtopie.space"
        loglevel.value = options["loglevel"] ?: "debug"
        upstreamSocks.text = options["upstreamSocks"] ?: ""
        ipv6Support.isChecked = options["ipv6_support"]?.toBoolean() ?: false
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        addPreferencesFromResource(R.xml.config)
        host.setOnBindEditTextListener { it.inputType = InputType.TYPE_TEXT_VARIATION_URI }
        serverPort.setOnBindEditTextListener { it.inputType = InputType.TYPE_CLASS_NUMBER }

        password.setOnBindEditTextListener { editText ->
            editText.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            editText.postDelayed({
                editText.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                editText.setSelection(editText.text.length)
            }, 3000)
        }
        password.setOnPreferenceChangeListener { _, _ ->
            password.summary = "********"
            true
        }
        upstreamSocks.setOnBindEditTextListener { it.inputType = InputType.TYPE_TEXT_VARIATION_URI }
    }

    fun setEditable(editable: Boolean) {
        preferenceScreen.isEnabled = editable
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        ViewCompat.setOnApplyWindowInsetsListener(listView) { v, insets ->
            insets.apply {
                v.updatePadding(bottom = getInsets(WindowInsetsCompat.Type.navigationBars()).bottom)
            }
        }
    }

    private fun onModeChange(modeValue: String) {
        // no-op: no UI elements depend on mode changes after websocket removal
    }
    override fun onPreferenceChange(preference: Preference, newValue: Any?): Boolean {
        onModeChange(newValue as String)
        return true
    }

    override fun onDisplayPreferenceDialog(preference: Preference) {
        super.onDisplayPreferenceDialog(preference)
    }

}
