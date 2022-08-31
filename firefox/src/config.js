

const defaultConfig = {
    enabled: false,
    useBurpProxy: false,
    addContainerHeader: true,
    injectToolbox: false,
    logPostMessage: true,
    removeSecurityHeaders: false,
    burpProxyHost: '127.0.0.1',
    burpProxyPort: '8080',
    activeToolbox: null,
    savedToolbox: {},
    devToolDual: false,
    activeMessageFunc: "noop",
    savedMessageFunc: {
        "noop": `/* 
* Available parameters: 
*   data: the message data
*   origin: the origin frame
*   destination: the destination frame
*
* return: 
*   new modified message to display
*/
    
return data
`}
}


const config = {
    async get(key) {
        const r = await browser.storage.local.get(key)
        return r[key] ?? defaultConfig[key]
    },
    async set(key, value) {
        return await browser.storage.local.set({ [key]: value })
    },
    onChange(key, handler) {
        return browser.storage.onChanged.addListener((changes, areaName) => {
            if (areaName != "local") return

            for (const [name, { newValue }] of Object.entries(changes)) {
                if (name != key) continue
                handler(newValue)
            }
        })
    }
}