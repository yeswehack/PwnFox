

/* Containers Identity */
async function getOrCreateIdentity(color) {
    const name = `PwnFox-${color}`
    const icon = "fingerprint"
    const [identity] = await browser.contextualIdentities.query({ name })
    if (identity !== undefined) {
        return identity
    }
    return await browser.contextualIdentities.create({ name, color, icon })
}

async function createContainerTab(color) {
    const identity = await getOrCreateIdentity(color)
    const { cookieStoreId } = identity
    return browser.tabs.create({ cookieStoreId })
}

function bindCheckboxToConfig(selector, config, configName){
    const checkbox = document.querySelector(selector)
    checkbox.checked = config[configName]
    checkbox.addEventListener("change", () => config[configName] = checkbox.checked)
}



function createContainerTabButtons() {
    const colors = [
        "blue",
        "turquoise",
        "green",
        "yellow",
        "orange",
        "red",
        "pink",
        "purple"
    ]
    const container = document.querySelector("#identities")
    colors.forEach(color => {
        const div = document.createElement("div")
        div.classList.add("identity", color)
        div.addEventListener("click", ev => {
            createContainerTab(color)
        })
        container.appendChild(div)
    })

}

async function togglePwnfox(enabled) {
    const color = enabled ? "#00ff00" : "#ff0000"
    const [canvas] = await createIcon(color)
    const iconContainer = document.getElementById("icon")
    iconContainer.replaceChild(canvas, iconContainer.firstChild)

    const main = document.querySelector("main")
    if (!enabled) {
        main.classList.add('disabled')
    } else {
        main.classList.remove('disabled')
    }
}

async function main() {
    const config = await getConfig()

    createContainerTabButtons()
    
    bindCheckboxToConfig("#option-enabled", config, "enabled")
    bindCheckboxToConfig("#option-useBurpProxy", config, "useBurpProxy")
    bindCheckboxToConfig("#option-addContainerHeader", config, "addContainerHeader")
    bindCheckboxToConfig("#option-removeSecurityHeaders", config, "removeSecurityHeaders")
    bindCheckboxToConfig("#option-injectToolbox", config, "injectToolbox")

    /* Hook settings link */
    document.querySelector("#settings").addEventListener("click", ev => {
        browser.runtime.openOptionsPage()
    })

    const select = document.getElementById("select-toolbox")
    const filenames = Object.keys(config.savedToolbox)
    for (const filename of filenames) {
        const option = document.createElement("option")
        option.value = filename
        option.selected = filename === config.activeToolbox
        option.innerText = filename
        select.appendChild(option)
    }
    select.addEventListener("change", () => {
        config.activeToolbox = select.value
    })
    config.addListener('enabled', togglePwnfox, true)
}

window.addEventListener("load", main)







