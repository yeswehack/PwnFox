/* Communication from contentScript to devtools */

const Coms = new class {
    constructor() {
        this.ports = {}
    }

    connect(port) {
        this.ports[port.name] = port
        port.onDisconnect.addListener(p => {
            delete this.ports[p.name]
        })
    }

    postMessage(name, message) {
        if (this.ports[name])
            this.ports[name].postMessage(message)
    }
}

function handleMessage(message, sender) {
    Coms.postMessage(`devtools-${sender.tab.id}`, message)
}




/* */

async function main() {
    const config = await getConfig();
    const features = new BackgroundFeatures(config)

    features.maybeStart()

    browser.runtime.onConnect.addListener(port => Coms.connect(port))
    browser.runtime.onMessage.addListener(handleMessage);
}

window.addEventListener("load", main)