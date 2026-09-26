// Vulnerable JavaScript sample
const child_process = require('child_process');

const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuv";

function renderReport(req, res) {
    const userInput = req.query.code;
    // Vulnerability: Dangerous eval execution (CWE-502)
    return eval(userInput);
}

function executeScript(req, res) {
    const cmd = req.query.cmd;
    // Vulnerability: OS command injection (CWE-78)
    child_process.exec(cmd);
}
