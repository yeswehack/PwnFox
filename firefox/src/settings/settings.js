async function main() {
    const $ = i => document.getElementById(i)
    const config = await getConfig()

    const configEl = [
        [$("burphost"), "burpProxyHost"],
        [$("burpport"), "burpProxyPort"],
    ]

    /* Config to form */
    configEl.forEach(([el, configName]) => {
        el.value = config[configName]
    })

    /* Form to config */
    document.querySelector("form").addEventListener("submit", ev => {
        configEl.forEach(([el, configName]) => {
            config[configName] = el.value
        })
    });
    newFileSelection(config, "savedToolbox", "#savedToolbox", 'toolbox')
}

document.addEventListener("DOMContentLoaded", main)
