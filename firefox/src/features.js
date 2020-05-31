class Feature {
    constructor(config, configName) {
        this.config = config
        this.configName = configName
        this.started = false
        this.config.addListener(configName, v => {
            v ? this.start() : this.stop()
        })
    }

    maybeStart() {
        if (this.config[this.configName]) {
            this.start();
        } else {
            this.stop();
        }
    }

    start() {
        //console.log(`STARTING ${this.constructor.name}`)
        this.started = true
    }

    stop() {
        //console.log(`STOPING ${this.constructor.name}`)
        this.started = false
    }
}


/* Burp Proxy */

function proxify(config) {
    return function (e) {
        const host = config.burpProxyHost
        const port = config.burpProxyPort
        return {
            type: "http",
            host,
            port
        };
    }
}


class UseBurpProxy extends Feature {
    constructor(config) {
        super(config, 'useBurpProxy')
        this.proxy = proxify(config)
    }

    start() {
        browser.proxy.onRequest.addListener(this.proxy, { urls: ["<all_urls>"] })
        super.start()
    }

    stop() {
        browser.proxy.onRequest.removeListener(this.proxy)
        super.stop()
    }
}


/* Add Color Headers */


async function colorHeaderHandler(e) {
    if (e.tabId < 0) return

    const colorMap = {
        blue: "blue",
        turquoise: "cyan",
        green: "green",
        yellow: "yellow",
        orange: "orange",
        red: "red",
        pink: "pink",
        purple: "magenta",
    }
    const { cookieStoreId } = await browser.tabs.get(e.tabId)
    if (cookieStoreId === "firefox-default") {
        return {}
    }
    const identity = await browser.contextualIdentities.get(cookieStoreId)
    if (identity.name.startsWith("PwnFox-")) {
        const name = "X-PwnFox-Color"
        const value = colorMap[identity.color]
        e.requestHeaders.push({ name, value })
    }
    return { requestHeaders: e.requestHeaders }
}

class AddContainerHeader extends Feature {
    constructor(config) {
        super(config, 'addContainerHeader')
    }

    start() {
        browser.webRequest.onBeforeSendHeaders.addListener(colorHeaderHandler,
            { urls: ["<all_urls>"] },
            ["blocking", "requestHeaders"]
        );
        super.start()
    }

    stop() {
        browser.webRequest.onBeforeSendHeaders.removeListener(colorHeaderHandler)
        super.stop()
    }
}


/* Remove security Headers */
function removeHeaders(response) {
    const { responseHeaders: origHeaders } = response
    const blacklistedHeaders = [
        "Content-Security-Policy",
        "X-XSS-Protection",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]
    const newHeaders = origHeaders.filter(({ name }) => {
        return !blacklistedHeaders.includes(name)
    })
    return { responseHeaders: newHeaders }
}


class RemoveSecurityHeaders extends Feature {
    constructor(config) {
        super(config, 'removeSecurityHeaders')
    }

    start() {
        browser.webRequest.onHeadersReceived.addListener(removeHeaders,
            { urls: ["<all_urls>"] },
            ["blocking", "responseHeaders"]
        );
        super.start()
    }

    stop() {
        browser.webRequest.onHeadersReceived.removeListener(removeHeaders)
        super.stop()
    }
}

/* Toolbox */

class InjectToolBox extends Feature {
    constructor(config) {
        super(config, "injectToolbox")
        this.script = null
    }

    start() {
        const toolboxName = this.config.activeToolbox
        const toolbox = this.config.savedToolbox[toolboxName] || ""
        if (!toolbox.trim()) {
            return
        }

        this.script = document.createElement('script')
        this.script.textContent = toolbox;
        (document.head || document.documentElement).appendChild(this.script);
        super.start()
    }

    stop() {
        if (this.script) {
            this.script.parentElement.removeChild(this.script)
            this.script = null
        }
        super.stop()
    }

}


/* Post Message */
function logMessage({ data, origin }) {
    browser.runtime.sendMessage({ data, origin, destination: window.origin })
}

class LogPostMessage extends Feature {
    constructor(config) {
        super(config, "logPostMessage")
    }

    start() {
        window.addEventListener("message", logMessage);
        super.start()
    }

    stop() {
        window.removeEventListener("message", logMessage);
        super.stop()
    }
}

/* Global Enable */


class FeaturesGroup extends Feature {
    constructor(config, features) {
        super(config, "enabled")
        this.features = features
    }

    start() {
        this.features.forEach(f => f.maybeStart())
        super.start()
    }

    stop() {
        this.features.forEach(f => f.stop())
        super.stop()
    }
}


class BackgroundFeatures extends FeaturesGroup {
    constructor(config) {
        const features = [
            new UseBurpProxy(config),
            new AddContainerHeader(config),
            new RemoveSecurityHeaders(config)
        ]
        super(config, features)
    }

    start() {
        createIcon("#00ff00").then(([canvas, imageData]) => {
            browser.browserAction.setIcon({ imageData })
        })
        super.start()
    }

    stop() {
        createIcon("#ff0000").then(([canvas, imageData]) => {
            browser.browserAction.setIcon({ imageData })
        })
        super.stop()
    }
}


class ContentScriptFeatures extends FeaturesGroup {
    constructor(config) {
        const features = [
            new InjectToolBox(config),
            new LogPostMessage(config),
        ]
        super(config, features)
    }
}