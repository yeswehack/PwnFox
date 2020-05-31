package  burp

import java.io.PrintWriter

class BurpExtender : IBurpExtender, IHttpListener, IExtensionStateListener {

    lateinit var callbacks: IBurpExtenderCallbacks
    lateinit var helpers: IExtensionHelpers
    lateinit var stdout: PrintWriter
    lateinit var stderr: PrintWriter

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        this.helpers = callbacks.helpers
        this.stdout = PrintWriter(callbacks.stdout, true)
        this.stderr = PrintWriter(callbacks.stderr, true)

        callbacks.setExtensionName("PwnFox")
        callbacks.registerHttpListener(this)
        callbacks.registerExtensionStateListener(this)
        stdout.println("PwnFox Loaded")
    }


    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        if (!messageIsRequest) return
        val requestInfo = helpers.analyzeRequest(messageInfo)
        val body = messageInfo.request.drop(requestInfo.bodyOffset).toByteArray()
        val (pwnFoxHeaders, cleanHeaders) = requestInfo.headers.partition {
            it.startsWith("X-PwnFox-")
        }

        pwnFoxHeaders.forEach() {
            if (it.startsWith(("X-PwnFox-Color:"))) {
                val (_, color) = it.split(":", limit = 2)
                messageInfo.highlight = color.trim()
            }
        }

        messageInfo.request =
            helpers.buildHttpMessage(cleanHeaders, body)

    }

    override fun extensionUnloaded() {
    }
}




