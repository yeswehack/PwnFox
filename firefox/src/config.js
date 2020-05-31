

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
    savedMessageFunc: {"noop": `/* 
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

function chainMap(...maps) {
    return new Proxy({}, {
        get(target, key) {
            for (const map of [target, ...maps]) {
                if (key in map) {
                    return Reflect.get(map, key)
                }
            }
            return undefined
        },
        has(target, key) {
            return [target, ...maps].some(map => Reflect.has(map, key))
        },
        ownKeys(target){
            const keys = new Set()
            for (const map of [target, ...maps]){
                Reflect.ownKeys(map).forEach(k => keys.add(k))
            }
            return Array.from(keys)
        },
        set(target, key ,value){
            return Reflect.set(target, key, value);
        }
    })
}

async function getConfig() {
    const STORAGE_AREA = "local"
    const callbacks = {}
    const loadedConfig = await browser.storage[STORAGE_AREA].get()
    const config = chainMap(loadedConfig, defaultConfig)



    function addListener(name, handler, immediateCall = false) {
        if (!(name in callbacks)) {
            callbacks[name] = []
        }
        callbacks[name].push(handler)
        if (immediateCall){
            handler(config[name])
        }
    }


    browser.storage.onChanged.addListener((changes, areaName) => {
        if (areaName !== STORAGE_AREA) return
        for (const [name, {newValue}] of Object.entries(changes)) {
            if (name in callbacks) {
                callbacks[name].forEach(handler => handler(newValue))
            }
        }
    })


    return new Proxy(config, {
        get(target, key) {
            if (key === "addListener") {
                return addListener
            }
            return Reflect.get(target, key)
        },
        set(target, key, value) {
            browser.storage.local.set({ [key]: value })
            return Reflect.set(target, key, value)
        }
    })
}