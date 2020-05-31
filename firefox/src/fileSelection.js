


function newFileSelection(config, storeName, selector, defaultName) {
    const el = document.querySelector(selector)
    const select = el.querySelector("select")
    const files = config[storeName];

    const newBtn = el.querySelector(".file-list-new")
    const saveBtn = el.querySelector(".file-list-save")
    const deleteBtn = el.querySelector(".file-list-delete")
    const editBtn = el.querySelector(".file-list-edit")
    const textarea = el.querySelector("textarea")
    /* Utils */

    function createOption(filename) {
        const option = document.createElement("option")
        option.innerText = filename
        option.value = filename
        return option
    }

    function preventDuplicate(filenames, newName) {
        let idx = 2;
        let testName = newName
        while (testName in filenames) {
            testName = `${newName} (${idx})`
            idx += 1;
        }
        return testName
    }
    function addShadow() {
        if (textarea.value !== files[select.value]) {
            textarea.classList.add("changed")
        } else {
            textarea.classList.remove("changed")
        }
    }
    /* File operations */

    function addFile(filename, content) {
        select.appendChild(createOption(filename))
        saveFile(filename, content)
        textarea.disabled = select.children.length === 0
        select.value = filename
        showFile(filename)
    }

    function saveFile(filename, content) {
        files[filename] = content
        config[storeName] = files
    }

    function removeFile(filename) {
        const toRemove = Array.from(select.children).find(c => c.value === filename)
        select.removeChild(toRemove)
        delete files[filename]
        config[storeName] = files
        textarea.disabled = select.children.length === 0
    }

    function showFile(filename) {
        textarea.value = files[filename] || ""
    }


    /* Handle file Selection */
    for (const filename of Object.keys(files)) {
        select.appendChild(createOption(filename))
    }


    /* Handle events  */
    select.addEventListener("change", ev => {
        showFile(select.value)
    })

    deleteBtn.addEventListener("click", ev => {
        ev.preventDefault()
        removeFile(select.value)
        showFile(select.value)
    })

    saveBtn.addEventListener("click", ev => {
        ev.preventDefault()
        const filename = select.value
        const content = textarea.value
        saveFile(filename, content)
        addShadow()
    })

    newBtn.addEventListener("click", ev => {
        ev.preventDefault()
        const response = window.prompt("name ?", defaultName).trim()
        if (!response) return
        const filename = preventDuplicate(files, response)
        addFile(filename, "")
    })

    editBtn.addEventListener("click", ev => {
        ev.preventDefault()
        const oldName = select.value
        const response = window.prompt("rename to ?", oldName).trim()
        if (!response || response === oldName) return
        const newName = preventDuplicate(files, response)
        const oldContent = files[oldName]
        removeFile(oldName)
        addFile(newName, oldContent)
    })

    textarea.addEventListener("keydown", ev => {

        /* ctrl+s -> save */
        if (ev.ctrlKey && ev.key === "s") {
            ev.preventDefault()
            const filename = select.value
            const content = textarea.value
            saveFile(filename, content)
        }

        addShadow()
    })
    
    textarea.addEventListener("keyup", addShadow)


    showFile(select.value)
    textarea.disabled = select.children.length === 0
}

