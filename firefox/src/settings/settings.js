async function main() {
    const $ = i => document.getElementById(i)

    const configEl = [
        [$("burphost"), "burpProxyHost"],
        [$("burpport"), "burpProxyPort"],
    ]


    /* Config to form */
    configEl.forEach(([el, configName]) => {
        config.get(configName).then(v => el.value = v)
    })

    /* Form to config */
    document.querySelector("form").addEventListener("submit", ev => {
        configEl.forEach(([el, configName]) => {
            config.set(configName, el.value)
        })
    });
    newFileSelection(config, "savedToolbox", "#savedToolbox", 'toolbox')
}

document.addEventListener("DOMContentLoaded", main)
