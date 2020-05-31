
/* Create a filter function and store the compiled version */
const func_cache = {}
function getFilterFunction(config) {
  const funcName = config.activeMessageFunc
  const funcSrc = config.savedMessageFunc[funcName] || "return data"
  if (!(funcSrc in func_cache)) {
    func_cache[funcSrc] = new Function("data", "origin", "destination", funcSrc)
  }
  return func_cache[funcSrc]
}

function createCell(txt) {
  const cell = document.createElement("span")
  cell.innerText = txt
  return cell
}

function createDetailsContent(origin, destination, message) {
  const content = document.createElement("div")
  content.classList.add("message-details-content")


  const oriTitle = createCell("Origin")
  const ori = document.createElement("span")
  ori.innerText = origin


  const destTitle = createCell("Destination")
  const dest = document.createElement("span")
  dest.innerText = destination

  const msgTitle = createCell("Message")
  const msg = document.createElement("span")
  msg.innerText = typeof message === "string" ? message : JSON.stringify(message, null, 2)


  content.appendChild(oriTitle)
  content.appendChild(ori)
  content.appendChild(destTitle)
  content.appendChild(dest)
  content.appendChild(msgTitle)
  content.appendChild(msg)
  return content
}

function stripProtocol(s) {
  if (s.startsWith('http://')) {
    return s.substr(7)
  }
  if (s.startsWith('https://')) {
    return s.substr(8)
  }
  return s
}

function createRow(origin, dest, msg, time) {
  const details = document.createElement("details")
  const summary = document.createElement("summary")

  details.open = false
  summary.classList.add("row")
  summary.appendChild(createCell(""))
  summary.appendChild(createCell(stripProtocol(origin)))
  summary.appendChild(createCell(stripProtocol(dest)))
  summary.appendChild(createCell(typeof msg === "string" ? msg : JSON.stringify(msg)))
  summary.appendChild(createCell(time))
  details.appendChild(summary)
  details.appendChild(createDetailsContent(origin, dest, msg))
  return details
}

function addRow(origin, dest, msg, time) {
  const container = document.querySelector("#message-list")
  container.appendChild(createRow(origin, dest, msg, time))
}

function createMessageHandler(config) {
  return function handleMessage(message) {
    const date = new Date()
    const h = date.getHours().toString().padStart(2, "0")
    const m = date.getMinutes().toString().padStart(2, "0")
    const s = date.getSeconds().toString().padStart(2, "0")
    const time = `${h}:${m}:${s}`
    const filterFunction = getFilterFunction(config)
    try {
      const data = filterFunction(message.data, message.origin, message.destination)
      if (data === null) return
      addRow(message.origin, message.destination, data, time)
    } catch (e) {
      addRow(message.origin, message.destination, `ERROR: ${e.toString()}`, time)
    }

  }
}


async function main() {
  const config = await getConfig()
  const $ = sel => document.querySelector(sel)
  const $$ = sel => Array.from(document.querySelectorAll(sel))

  window.handleMessage = createMessageHandler(config)
  
  /* Top left buttons */
  $("#btn-clear").addEventListener("click", () => {
    $("#message-list").innerHTML = ""
  })
  $("#btn-shrink").addEventListener("click", () => {
    Array.from($$("details")).forEach(el => el.open = false)
  })
  $("#btn-expand").addEventListener("click", () => {
    Array.from($$("details")).forEach(el => el.open = true)
  })


  /* toggle panel */
  if (config.devToolDual){
    $("main").classList.add("dual")
  }
  $("#toggleDual").addEventListener("click", () => {
    $("main").classList.toggle("dual")
    config.devToolDual = $("main").classList.contains("dual")
  })


  /* Right panel */
  newFileSelection(config, "savedMessageFunc", "#savedMessageFunc", "filter")
  
  const select = $("#savedMessageFunc select")
  Array.from(select.children).find(c => c.selected = c.value === config.activeMessageFunc) 
  select.addEventListener("change", () => {
    config.activeMessageFunc = select.value
  })

  const textarea = $("#savedMessageFunc textarea")
  textarea.value = config.savedMessageFunc[config.activeMessageFunc] || ""
}

window.addEventListener("DOMContentLoaded", main)