package  burp

import java.io.PrintWriter
import java.util.*

class BurpExtender : IBurpExtender, IProxyListener, IExtensionStateListener {

    private lateinit var callbacks: IBurpExtenderCallbacks
    private lateinit var helpers: IExtensionHelpers
    private lateinit var stdout: PrintWriter
    private lateinit var stderr: PrintWriter

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        this.helpers = callbacks.helpers
        this.stdout = PrintWriter(callbacks.stdout, true)
        this.stderr = PrintWriter(callbacks.stderr, true)

        callbacks.setExtensionName("PwnFox")
        callbacks.registerExtensionStateListener(this)
        callbacks.registerProxyListener(this)
        stdout.println("PwnFox Loaded")
    }


    override fun extensionUnloaded() {
    }

    override fun processProxyMessage(messageIsRequest: Boolean, message: IInterceptedProxyMessage?) {
        if (!messageIsRequest) return

        val messageInfo = message?.messageInfo
        if (messageInfo != null) {

            val requestInfo = helpers.analyzeRequest(messageInfo)
            val body = messageInfo.request.drop(requestInfo.bodyOffset).toByteArray()
            val (pwnFoxHeaders, cleanHeaders) = requestInfo.headers.partition {
                it.lowercase(Locale.getDefault()).startsWith("x-pwnfox-")
            }

            pwnFoxHeaders.forEach() {
                if (it.lowercase(Locale.getDefault()).startsWith(("x-pwnfox-color:"))) {
                    val (_, color) = it.split(":", limit = 2)
                    messageInfo.highlight = color.trim()
                }
            }
            messageInfo.request = helpers.buildHttpMessage(cleanHeaders, body)
        }
    }
}