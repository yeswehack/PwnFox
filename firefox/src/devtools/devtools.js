const title = "Messages"
const icon = "/icons/icon.svg"
const panel = "/src/devtools/panel/panel.html"


browser.devtools.panels.create(title, icon, panel).then(panel => {
  const port = chrome.runtime.connect({ name: `devtools-${browser.devtools.inspectedWindow.tabId}` });
  let messageHistory = [];
  let _window = null

  port.onMessage.addListener(function (msg) {
    if (_window) {
      _window.handleMessage(msg);
    } else {
      messageHistory.push(msg);
    }
  });

  panel.onShown.addListener(function (panelWindow) {
    panel.onShown.removeListener(this);
    _window = panelWindow
    let msg;
    while (msg = messageHistory.shift()) {
      _window.handleMessage(msg)
    }
  });
})