class PwnfoxGitChecker {
  static GIT_HEAD_HEADER = "ref: refs/heads/";
  static KEY = "pwnfoxGitCheckedAt";
  static INTERVAL = 60 * 60 * 24;

  static timestamp() {
    return new Date().getTime() / 1000;
  }

  static getPaths() {
    try {
      const data = JSON.parse(localStorage.getItem(PwnfoxGitChecker.KEY));
      if (data == null) return {};
      return data;
    } catch (_) {
      return {};
    }
  }

  static addPath(path) {
    const paths = PwnfoxGitChecker.getPaths();

    paths[path] = PwnfoxGitChecker.timestamp();
    localStorage.setItem(PwnfoxGitChecker.KEY, JSON.stringify(paths));
  }

  static hasToBeChecked(path) {
    const paths = PwnfoxGitChecker.getPaths();

    // No entry yet
    if (!(path in paths)) return true;

    const ts = paths[path];

    // Expired
    const now = PwnfoxGitChecker.timestamp();
    if (now - PwnfoxGitChecker.INTERVAL > ts) return true;

    return false;
  }

  static async checkPath(path) {
    while (path.endsWith("/")) {
      path = path.slice(0, -1);
    }

    const url = `${path}/.git/HEAD`;

    if (!PwnfoxGitChecker.hasToBeChecked(url)) return false;

    const response = await fetch(url);

    PwnfoxGitChecker.addPath(url);

    if (
      response.status === 200 &&
      (await response.text()).startsWith(PwnfoxGitChecker.GIT_HEAD_HEADER)
    ) {
      PwnfoxGitChecker.triggerNotification(url);
      return true;
    }
    return false;
  }

  static async run() {
    await PwnfoxGitChecker.checkPath(location.pathname);
  }

  static triggerNotification(path) {
    alert(`GitDetector: Possible '.git/' exposed @ '${path}'!`);
  }
}

PwnfoxGitChecker.run();
