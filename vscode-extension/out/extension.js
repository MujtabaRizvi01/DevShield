"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const axios_1 = __importDefault(require("axios"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const crypto = __importStar(require("crypto"));
const DEFAULT_API = 'http://127.0.0.1:8001';
// ─────────────────────────────────────────────────────────────────────────────
// API KEY MANAGEMENT
//
// Each VS Code installation generates a unique API key on first activation.
// The key is stored in VS Code's globalStorageUri (a private folder that
// persists across sessions but is NOT inside the workspace — users never
// accidentally commit it).
//
// Format: ds_<40 random hex chars>
// The backend auto-registers any key with this format on first use.
// ─────────────────────────────────────────────────────────────────────────────
function getOrCreateApiKey(ctx) {
    const keyFile = path.join(ctx.globalStorageUri.fsPath, 'api_key.txt');
    fs.mkdirSync(ctx.globalStorageUri.fsPath, { recursive: true });
    if (fs.existsSync(keyFile)) {
        const existing = fs.readFileSync(keyFile, 'utf-8').trim();
        if (existing.startsWith('ds_') && existing.length === 43) {
            return existing;
        }
    }
    // Generate a new key: ds_ + 40 random hex chars
    const key = 'ds_' + crypto.randomBytes(20).toString('hex');
    fs.writeFileSync(keyFile, key, 'utf-8');
    console.log('[DevShield] Generated new API key');
    return key;
}
// ─────────────────────────────────────────────────────────────────────────────
// FIX: Critical Issue #3 — User consent + .devshieldignore support
//
// CONSENT
// ───────
// On first activation we show a one-time notice telling the user that their
// code will be sent to Groq's API for analysis.  They must click "I Agree"
// before any code is ever transmitted.  The consent flag is stored in
// VS Code's workspaceState so consent is asked every session (resets on window close).
//
// .devshieldignore
// ────────────────
// If a .devshieldignore file exists in the workspace root, files matching
// any of its glob patterns are silently skipped — no code is sent to the
// backend for those files.  The format is identical to .gitignore.
// Example .devshieldignore:
//   secrets.py
//   **/config/credentials.*
//   .env*
// ─────────────────────────────────────────────────────────────────────────────
function ensureConsent(ctx) {
    return __awaiter(this, void 0, void 0, function* () {
        const CONSENT_KEY = 'devshield.userConsented';
        if (ctx.workspaceState.get(CONSENT_KEY)) {
            return true;
        }
        const response = yield vscode.window.showInformationMessage('DevShield sends your code to Groq\'s API (an external AI service) for security analysis. ' +
            'This includes the full contents of every file you save.\n\n' +
            'To exclude sensitive files (passwords, keys, confidential code), create a ' +
            '.devshieldignore file in your workspace root and list files or patterns to skip ' +
            '(same format as .gitignore). Example:\n' +
            '  secrets.py\n  *.env\n  config/credentials.*\n\n' +
            'Click \'Learn More\' to see full documentation.', { modal: true }, 'I Agree', 'Learn More', 'Decline');
        if (response === 'I Agree') {
            yield ctx.workspaceState.update(CONSENT_KEY, true);
            return true;
        }
        if (response === 'Learn More') {
            vscode.env.openExternal(vscode.Uri.parse('https://github.com/your-repo/devshield#devshieldignore'));
            // Ask again after they have read the docs
            return ensureConsent(ctx);
        }
        vscode.window.showWarningMessage('DevShield is disabled — code analysis requires consent. ' +
            'Reload the window to be asked again.');
        return false;
    });
}
function isIgnored(filePath) {
    /**
     * Returns true if the file matches any pattern in .devshieldignore.
     * Uses simple glob matching without requiring extra dependencies.
     */
    const ws = vscode.workspace.workspaceFolders;
    if (!ws || !ws.length) {
        return false;
    }
    const ignoreFile = path.join(ws[0].uri.fsPath, '.devshieldignore');
    if (!fs.existsSync(ignoreFile)) {
        return false;
    }
    try {
        const lines = fs.readFileSync(ignoreFile, 'utf-8')
            .split('\n')
            .map(l => l.trim())
            .filter(l => l && !l.startsWith('#'));
        const rel = path.relative(ws[0].uri.fsPath, filePath).replace(/\\/g, '/');
        const fname = path.basename(filePath);
        for (const pattern of lines) {
            // Simple matching: exact filename, exact relative path, or wildcard prefix
            if (pattern === fname) {
                return true;
            }
            if (pattern === rel) {
                return true;
            }
            if (pattern.startsWith('**/') && fname === pattern.slice(3)) {
                return true;
            }
            if (pattern.endsWith('*') && fname.startsWith(pattern.slice(0, -1))) {
                return true;
            }
            if (pattern.startsWith('*.') && fname.endsWith(pattern.slice(1))) {
                return true;
            }
        }
    }
    catch (_a) { }
    return false;
}
let vulnerabilitiesMap = {};
let API_KEY = '';
let dastScans = new Map();
function getDevshieldDir(ctx) {
    const ws = vscode.workspace.workspaceFolders;
    return (ws === null || ws === void 0 ? void 0 : ws.length) ? path.join(ws[0].uri.fsPath, '.devshield') : ctx.globalStorageUri.fsPath;
}
function saveDastState(ctx) {
    try {
        const d = getDevshieldDir(ctx);
        fs.mkdirSync(d, { recursive: true });
        const scansArray = Array.from(dastScans.values());
        fs.writeFileSync(path.join(d, 'dast_state.json'), JSON.stringify(scansArray), 'utf-8');
    }
    catch (_a) { }
}
function loadDastState(ctx) {
    try {
        const f = path.join(getDevshieldDir(ctx), 'dast_state.json');
        if (!fs.existsSync(f)) {
            return;
        }
        const scansArray = JSON.parse(fs.readFileSync(f, 'utf-8'));
        if (Array.isArray(scansArray)) {
            for (const scan of scansArray) {
                // Only restore done/error scans, not scanning ones
                if (scan.status !== 'scanning') {
                    // Verify report file still exists
                    if (scan.status === 'done' && scan.reportPath && !fs.existsSync(scan.reportPath)) {
                        continue;
                    }
                    dastScans.set(scan.id, scan);
                }
            }
        }
    }
    catch (_a) { }
}
function getReportDir(ctx) {
    return path.join(getDevshieldDir(ctx), 'dast_reports');
}
/**
 * Keep only the `keep` most recent HTML reports in the folder.
 * Deletes the oldest files when the count exceeds the limit.
 * Called after saving each new report.
 */
function cleanupOldReports(reportDir, keep = 5) {
    try {
        if (!fs.existsSync(reportDir)) {
            return;
        }
        const files = fs.readdirSync(reportDir)
            .filter(f => f.endsWith('.html'))
            .map(f => ({ name: f, time: fs.statSync(path.join(reportDir, f)).mtimeMs }))
            .sort((a, b) => a.time - b.time); // oldest first
        // Delete oldest files until only `keep` remain
        while (files.length > keep) {
            const oldest = files.shift();
            if (oldest) {
                fs.unlinkSync(path.join(reportDir, oldest.name));
                console.log('[DevShield] Deleted old report:', oldest.name);
            }
        }
    }
    catch (e) {
        console.error('[DevShield] cleanupOldReports error:', e);
    }
}
// ─────────────────────────────────────────────────────────────────────────────
// Axios helper — always injects X-API-Key header
//
// This is the key change for multi-user support.  Every single request to
// the backend carries the user's unique API key so the server knows which
// user's storage folder to read/write.
// ─────────────────────────────────────────────────────────────────────────────
function apiHeaders() {
    return { 'X-API-Key': API_KEY };
}
// ─────────────────────────────────────────────────────────────────────────────
// Decorations — severity-based colors
// ─────────────────────────────────────────────────────────────────────────────
const decHigh = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255,50,50,0.18)',
    border: '1px solid rgba(255,50,50,0.5)',
    borderRadius: '2px',
    overviewRulerColor: 'rgba(255,50,50,0.9)',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: { contentText: ' \u25CF HIGH', color: 'rgba(255,80,80,0.8)', margin: '0 0 0 8px', fontStyle: 'italic' },
});
const decMedium = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255,165,0,0.15)',
    border: '1px solid rgba(255,165,0,0.45)',
    borderRadius: '2px',
    overviewRulerColor: 'rgba(255,165,0,0.9)',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: { contentText: ' \u25CF MEDIUM', color: 'rgba(255,165,0,0.8)', margin: '0 0 0 8px', fontStyle: 'italic' },
});
const decLow = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(100,200,100,0.12)',
    border: '1px solid rgba(100,200,100,0.35)',
    borderRadius: '2px',
    overviewRulerColor: 'rgba(100,200,100,0.8)',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: { contentText: ' \u25CF LOW', color: 'rgba(100,200,100,0.8)', margin: '0 0 0 8px', fontStyle: 'italic' },
});
function makeDec(v, editor) {
    const li = v.line - 1;
    const range = new vscode.Range(li, 0, li, editor.document.lineAt(li).text.length);
    const icon = v.severity === 'high' ? '\uD83D\uDD34' : v.severity === 'medium' ? '\uD83D\uDFE1' : '\uD83D\uDFE2';
    const md = new vscode.MarkdownString();
    md.appendMarkdown(icon + ' **' + String(v.issue || '') + '** (' + String(v.severity || 'medium').toUpperCase() + ')\n\n' + String(v.explanation || '') + '\n\n\uD83D\uDCA1 **Fix:** ' + String(v.suggested_fix || ''));
    return { range, hoverMessage: md };
}
function applyDecorations(editor) {
    const fname = path.basename(editor.document.fileName);
    const vulns = vulnerabilitiesMap[fname] || [];
    if (!vulns.length) {
        editor.setDecorations(decHigh, []);
        editor.setDecorations(decMedium, []);
        editor.setDecorations(decLow, []);
        return;
    }
    const valid = vulns.filter(v => v.line >= 1 && v.line <= editor.document.lineCount);
    editor.setDecorations(decHigh, valid.filter(v => v.severity === 'high').map(v => makeDec(v, editor)));
    editor.setDecorations(decMedium, valid.filter(v => v.severity === 'medium').map(v => makeDec(v, editor)));
    editor.setDecorations(decLow, valid.filter(v => v.severity === 'low').map(v => makeDec(v, editor)));
}
// ─────────────────────────────────────────────────────────────────────────────
// Tree view — FileNode and DastNode for parent-child relationships
// ─────────────────────────────────────────────────────────────────────────────
class FileNode extends vscode.TreeItem {
    constructor(fileKey, count) {
        super(fileKey, vscode.TreeItemCollapsibleState.Collapsed);
        this.fileKey = fileKey;
        this.description = count + (count === 1 ? ' issue' : ' issues');
        this.iconPath = 'warning';
        // Add a context value to enable the delete button in the tree
        this.contextValue = 'fileNode';
    }
}
// ─────────────────────────────────────────────────────────────────────────────
// DAST tree node — stores scan ID for parent-child relationships
// ─────────────────────────────────────────────────────────────────────────────
class DastNode extends vscode.TreeItem {
    constructor(scanId, label, collapsible = vscode.TreeItemCollapsibleState.None) {
        super(label, collapsible);
        this.scanId = scanId;
        this.contextValue = 'dastNode_' + scanId;
    }
}
class SecurityProvider {
    constructor() {
        this._ev = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._ev.event;
    }
    refresh() { this._ev.fire(undefined); }
    getTreeItem(el) { return el; }
    getChildren(el) {
        try {
            // Root level — list files with vulnerabilities
            if (!el) {
                const files = Object.keys(vulnerabilitiesMap).filter(k => {
                    const list = vulnerabilitiesMap[k];
                    return Array.isArray(list) && list.length > 0;
                });
                // Always return at least one item so the tree renders
                // (returning [] shows viewsWelcome which hides the tree entirely)
                if (!files.length) {
                    const empty = new vscode.TreeItem('No vulnerabilities found');
                    empty.iconPath = 'pass';
                    empty.description = 'Save a file to analyze it';
                    return Promise.resolve([empty]);
                }
                const items = files.map(f => {
                    const node = new FileNode(f, vulnerabilitiesMap[f].length);
                    // Auto-expand so vulnerabilities are immediately visible
                    node.collapsibleState = vscode.TreeItemCollapsibleState.Expanded;
                    return node;
                });
                return Promise.resolve(items);
            }
            // Child level — list vulnerabilities for a file
            if (el instanceof FileNode) {
                const vulns = Array.isArray(vulnerabilitiesMap[el.fileKey])
                    ? vulnerabilitiesMap[el.fileKey]
                    : [];
                return Promise.resolve(vulns.map(v => {
                    const severityIcon = v.severity === 'high' ? 'error'
                        : v.severity === 'medium' ? 'warning' : 'info';
                    const it = new vscode.TreeItem('Line ' + v.line + ': ' + String(v.issue || 'Unknown'), vscode.TreeItemCollapsibleState.None);
                    it.tooltip = String(v.explanation || '') + '\n\nFix: ' + String(v.suggested_fix || '');
                    it.description = String(v.severity || 'medium');
                    it.iconPath = severityIcon;
                    it.command = {
                        title: 'Go to line',
                        command: 'devshield.openLine',
                        arguments: [el.fileKey, v.line]
                    };
                    return it;
                }));
            }
            return Promise.resolve([]);
        }
        catch (err) {
            console.error('[DevShield] SecurityProvider.getChildren error:', err);
            const failure = new vscode.TreeItem('DevShield: failed to load issues');
            failure.iconPath = 'error';
            failure.description = 'Check Developer Tools console';
            return Promise.resolve([failure]);
        }
    }
}
class DastProvider {
    constructor(ctx) {
        this.ctx = ctx;
        this._ev = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._ev.event;
    }
    refresh() { this._ev.fire(undefined); }
    getTreeItem(el) { return el; }
    getChildren(el) {
        var _a;
        const items = [];
        // Root level — show all scans
        if (!el) {
            if (dastScans.size === 0) {
                return Promise.resolve(items);
            }
            for (const [scanId, scan] of dastScans) {
                if (scan.status === 'scanning') {
                    const s = new DastNode(scanId, '⏳ Scanning: ' + scan.url);
                    s.iconPath = 'loading~spin';
                    s.description = 'Please wait...';
                    s.collapsibleState = vscode.TreeItemCollapsibleState.Collapsed;
                    items.push(s);
                }
                else if (scan.status === 'done') {
                    const d = new DastNode(scanId, '✓ ' + scan.url);
                    d.iconPath = 'pass';
                    d.description = 'Scan complete';
                    d.collapsibleState = vscode.TreeItemCollapsibleState.Collapsed;
                    items.push(d);
                }
                else if (scan.status === 'error') {
                    const e = new DastNode(scanId, '❌ ' + scan.url);
                    e.iconPath = 'error';
                    e.description = ((_a = scan.message) === null || _a === void 0 ? void 0 : _a.slice(0, 50)) || 'Scan failed';
                    e.tooltip = scan.message;
                    e.collapsibleState = vscode.TreeItemCollapsibleState.Collapsed;
                    items.push(e);
                }
            }
            return Promise.resolve(items);
        }
        // Child level — show actions for a specific scan
        if (el instanceof DastNode) {
            const scan = dastScans.get(el.scanId);
            if (!scan) {
                return Promise.resolve([]);
            }
            if (scan.status === 'done') {
                const reportItem = new vscode.TreeItem('📄 Open Report');
                reportItem.command = { title: 'Open Report', command: 'devshield.openDastReport', arguments: [el.scanId] };
                reportItem.iconPath = 'link-external';
                reportItem.collapsibleState = vscode.TreeItemCollapsibleState.None;
                items.push(reportItem);
                const deleteItem = new vscode.TreeItem('🗑️ Delete');
                deleteItem.command = { title: 'Delete', command: 'devshield.deleteDastScan', arguments: [el.scanId] };
                deleteItem.iconPath = 'trash';
                deleteItem.collapsibleState = vscode.TreeItemCollapsibleState.None;
                items.push(deleteItem);
            }
            else if (scan.status === 'error') {
                const retryItem = new vscode.TreeItem('🔁 Retry Scan');
                retryItem.command = { title: 'Retry', command: 'devshield.retryDastScan', arguments: [scan.url] };
                retryItem.iconPath = 'refresh';
                retryItem.collapsibleState = vscode.TreeItemCollapsibleState.None;
                items.push(retryItem);
                const deleteItem = new vscode.TreeItem('🗑️ Delete');
                deleteItem.command = { title: 'Delete', command: 'devshield.deleteDastScan', arguments: [el.scanId] };
                deleteItem.iconPath = 'trash';
                deleteItem.collapsibleState = vscode.TreeItemCollapsibleState.None;
                items.push(deleteItem);
            }
            return Promise.resolve(items);
        }
        return Promise.resolve(items);
    }
}
// ─────────────────────────────────────────────────────────────────────────────
// Activate
// ─────────────────────────────────────────────────────────────────────────────
function activate(ctx) {
    // Generate / load this installation's unique API key
    API_KEY = getOrCreateApiKey(ctx);
    console.log('[DevShield] Active. User key prefix: ' + API_KEY.slice(0, 8) + '...');
    const apiBase = () => vscode.workspace.getConfiguration('devshield').get('backendUrl', DEFAULT_API);
    // ── Security panel ────────────────────────────────────────────────────────
    const secProvider = new SecurityProvider();
    const secView = vscode.window.createTreeView('devshieldSecurity', {
        treeDataProvider: secProvider,
        showCollapseAll: true,
    });
    ctx.subscriptions.push(secView);
    // ── Consent check (Fix #3) — must agree before any code is transmitted ────
    // ensureConsent() shows a one-time modal on first activation.
    // All code analysis is gated behind this check.
    let _userConsented = ctx.workspaceState.get('devshield.userConsented', false);
    (() => __awaiter(this, void 0, void 0, function* () {
        if (!_userConsented) {
            _userConsented = yield ensureConsent(ctx);
        }
    }))();
    function refreshAll() {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            applyDecorations(editor);
        }
        secProvider.refresh();
    }
    // ── On save → POST /analyze/ → parse vulnerabilities from response ────────
    //
    // Multi-user change: vulnerabilities now come back in the POST response
    // body directly.  No file paths, no disk reads — works on remote servers.
    const onSave = vscode.workspace.onDidSaveTextDocument((doc) => __awaiter(this, void 0, void 0, function* () {
        var _a, _b, _d, _e, _f, _g;
        const fname = path.basename(doc.fileName);
        const supported = ['.py', '.js', '.ts', '.java', '.php', '.go', '.rb', '.cs', '.cpp', '.c'];
        if (!supported.some(ext => fname.endsWith(ext))) {
            return;
        }
        // Fix #3a — skip if user has not consented
        if (!_userConsented) {
            _userConsented = yield ensureConsent(ctx);
            if (!_userConsented) {
                return;
            }
        }
        // Fix #3b — skip if file matches .devshieldignore
        if (isIgnored(doc.fileName)) {
            vscode.window.setStatusBarMessage('[DevShield] Skipped (in .devshieldignore): ' + fname, 3000);
            return;
        }
        vscode.window.setStatusBarMessage('[DevShield] Analyzing ' + fname + '...', 5000);
        try {
            const res = yield axios_1.default.post(apiBase() + '/analyze/', { filename: fname, code: doc.getText() }, { headers: apiHeaders(), timeout: 60000 });
            const vulns = Array.isArray((_a = res.data) === null || _a === void 0 ? void 0 : _a.vulnerabilities)
                ? res.data.vulnerabilities : [];
            vulnerabilitiesMap[fname] = vulns
                .filter((v) => v && typeof v.issue === 'string')
                .map((v) => ({
                issue: String(v.issue),
                line: Number(v.line) || 1,
                explanation: String(v.explanation || ''),
                suggested_fix: String(v.suggested_fix || ''),
                severity: String(v.severity || 'medium').toLowerCase(),
            }));
            console.log('[DevShield] ' + vulnerabilitiesMap[fname].length + ' vulns for ' + fname);
            const issueCount = (vulnerabilitiesMap[fname] || []).length;
            vscode.window.setStatusBarMessage('[DevShield] ' + issueCount + ' issue(s) in ' + fname, 5000);
            // Apply decorations then refresh panel twice for reliability
            const activeEd = vscode.window.visibleTextEditors.find(e => path.basename(e.document.fileName) === fname);
            if (activeEd) {
                applyDecorations(activeEd);
            }
            secProvider.refresh();
            setTimeout(() => secProvider.refresh(), 400);
        }
        catch (err) {
            const status = (_b = err === null || err === void 0 ? void 0 : err.response) === null || _b === void 0 ? void 0 : _b.status;
            const detail = ((_e = (_d = err === null || err === void 0 ? void 0 : err.response) === null || _d === void 0 ? void 0 : _d.data) === null || _e === void 0 ? void 0 : _e.detail) || ((_g = (_f = err === null || err === void 0 ? void 0 : err.response) === null || _f === void 0 ? void 0 : _f.data) === null || _g === void 0 ? void 0 : _g.error) || (err === null || err === void 0 ? void 0 : err.message) || 'Unknown';
            if (status === 429) {
                vscode.window.showWarningMessage('[DevShield] Rate limit hit — wait a moment before saving again.');
            }
            else if (status === 401) {
                vscode.window.showErrorMessage('[DevShield] Auth failed — your API key may be corrupted. Reload the window.');
            }
            else {
                vscode.window.setStatusBarMessage('[DevShield] Analysis failed: ' + String(detail), 5000);
            }
            console.error('[DevShield] analyze error:', detail);
        }
    }));
    ctx.subscriptions.push(onSave);
    // ── On startup: DO NOT restore results from MongoDB ────────────────────────
    // Security Panel starts empty on each session for privacy & clarity
    // This prevents showing old analysis results from previous sessions
    // Users can re-analyze files by saving them
    // Disabled auto-restore:
    // setTimeout(async () => {
    //   const res = await axios.get(apiBase() + '/analyze/all', { headers: apiHeaders() });
    //   ...restore logic...
    // }, 1500);
    // ── Re-apply decorations on tab switch ───────────────────────────────────
    vscode.window.onDidChangeActiveTextEditor(ed => { if (ed) {
        applyDecorations(ed);
    } });
    // ── Clear vulnerabilities when workspace changes ─────────────────────────────
    // Prevents vulnerabilities from old workspace showing in new workspace
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
        vulnerabilitiesMap = {};
        // Clear decorations from all visible editors
        vscode.window.visibleTextEditors.forEach(ed => {
            ed.setDecorations(decHigh, []);
            ed.setDecorations(decMedium, []);
            ed.setDecorations(decLow, []);
        });
        secProvider.refresh();
        console.log('[DevShield] Workspace changed, cleared old vulnerabilities');
    });
    // ── Hover ─────────────────────────────────────────────────────────────────
    vscode.languages.registerHoverProvider('*', {
        provideHover(doc, pos) {
            const fname = path.basename(doc.fileName);
            const v = (vulnerabilitiesMap[fname] || []).find(v => v.line === pos.line + 1);
            if (!v) {
                return null;
            }
            const md = new vscode.MarkdownString();
            md.appendMarkdown('**\u26A0\uFE0F ' + String(v.issue || '') + '**\n\n' + String(v.explanation || '') + '\n\n\uD83D\uDCA1 **Fix:** ' + String(v.suggested_fix || ''));
            return new vscode.Hover(md);
        }
    });
    // ── Quick fix ─────────────────────────────────────────────────────────────
    class QuickFix {
        provideCodeActions(doc, range, _c, _t) {
            const fname = path.basename(doc.fileName);
            const v = (vulnerabilitiesMap[fname] || []).find(v => v.line === range.start.line + 1);
            if (!v) {
                return [];
            }
            const fix = new vscode.CodeAction('Fix: ' + String(v.suggested_fix || ''), vscode.CodeActionKind.QuickFix);
            fix.edit = new vscode.WorkspaceEdit();
            fix.edit.insert(doc.uri, new vscode.Position(v.line - 1, 0), '# Fix: ' + String(v.suggested_fix || '') + '\n');
            return [fix];
        }
    }
    vscode.languages.registerCodeActionsProvider('*', new QuickFix());
    // ── Open line ─────────────────────────────────────────────────────────────
    vscode.commands.registerCommand('devshield.openLine', (fileKey, line) => {
        vscode.workspace.findFiles('**/' + fileKey, '**/node_modules/**', 1).then(uris => {
            if (!uris.length) {
                return;
            }
            vscode.window.showTextDocument(uris[0]).then(ed => {
                const pos = new vscode.Position(Math.max(0, line - 1), 0);
                ed.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
                ed.selection = new vscode.Selection(pos, pos);
            });
        });
    });
    // ── Create .devshieldignore command ─────────────────────────────────────
    // Shown as a button in the Security Panel when no ignore file exists.
    // Creates a .devshieldignore template in the workspace root and opens it.
    vscode.commands.registerCommand('devshield.createIgnoreFile', () => __awaiter(this, void 0, void 0, function* () {
        const ws = vscode.workspace.workspaceFolders;
        if (!ws || !ws.length) {
            vscode.window.showWarningMessage('DevShield: Open a workspace folder first.');
            return;
        }
        const ignoreFile = vscode.Uri.file(require('path').join(ws[0].uri.fsPath, '.devshieldignore'));
        // Check if already exists
        if (require('fs').existsSync(ignoreFile.fsPath)) {
            vscode.window.showTextDocument(ignoreFile);
            return;
        }
        // Create with helpful template content
        const template = [
            '# DevShield ignore file',
            '# Files matching these patterns will NOT be sent to the AI for analysis.',
            '# Format is identical to .gitignore.',
            '#',
            '# Examples:',
            '# secrets.py',
            '# *.env',
            '# config/credentials.*',
            '# *password*',
            '# private/**',
            '',
        ].join('\n');
        yield vscode.workspace.fs.writeFile(ignoreFile, Buffer.from(template, 'utf-8'));
        const doc = yield vscode.workspace.openTextDocument(ignoreFile);
        yield vscode.window.showTextDocument(doc);
        vscode.window.showInformationMessage('DevShield: .devshieldignore created! Add filenames or patterns to exclude from analysis.');
    }));
    // ── Remove file from security panel command ────────────────────────────────
    // Removes a specific file and its issues from the security panel
    vscode.commands.registerCommand('devshield.removeFileFromPanel', (node) => {
        const fileKey = node.fileKey;
        if (fileKey && vulnerabilitiesMap[fileKey]) {
            delete vulnerabilitiesMap[fileKey];
            // Clear decorations from all visible editors for this file
            vscode.window.visibleTextEditors.forEach(ed => {
                if (path.basename(ed.document.fileName) === fileKey) {
                    ed.setDecorations(decHigh, []);
                    ed.setDecorations(decMedium, []);
                    ed.setDecorations(decLow, []);
                }
            });
            secProvider.refresh();
            vscode.window.setStatusBarMessage('[DevShield] Removed ' + fileKey + ' from panel', 3000);
            console.log('[DevShield] Removed file from panel:', fileKey);
        }
    });
    // ── Fix #7: Rotate API key command ─────────────────────────────────────────
    vscode.commands.registerCommand('devshield.rotateKey', () => __awaiter(this, void 0, void 0, function* () {
        var _a, _b, _d;
        const confirm = yield vscode.window.showWarningMessage('Rotate your DevShield API key? Your current key will be permanently revoked ' +
            'and a new one generated. This cannot be undone.', { modal: true }, 'Rotate Key', 'Cancel');
        if (confirm !== 'Rotate Key') {
            return;
        }
        try {
            const res = yield axios_1.default.post(apiBase() + '/rotate-key', {}, { headers: apiHeaders(), timeout: 10000 });
            const newKey = ((_a = res.data) === null || _a === void 0 ? void 0 : _a.new_api_key) || '';
            if (!newKey) {
                throw new Error('No key returned');
            }
            // Save new key to globalStorageUri
            const keyFile = path.join(ctx.globalStorageUri.fsPath, 'api_key.txt');
            fs.writeFileSync(keyFile, newKey, 'utf-8');
            API_KEY = newKey;
            vscode.window.showInformationMessage('API key rotated successfully. Your new key has been saved automatically. ' +
                'Key prefix: ' + newKey.slice(0, 8) + '...');
        }
        catch (err) {
            vscode.window.showErrorMessage('Key rotation failed: ' + String(((_d = (_b = err === null || err === void 0 ? void 0 : err.response) === null || _b === void 0 ? void 0 : _b.data) === null || _d === void 0 ? void 0 : _d.detail) || (err === null || err === void 0 ? void 0 : err.message)));
        }
    }));
    // ── Debug ─────────────────────────────────────────────────────────────────
    vscode.commands.registerCommand('devshield.debugSast', () => {
        const keys = Object.keys(vulnerabilitiesMap);
        const total = keys.reduce((n, k) => n + vulnerabilitiesMap[k].length, 0);
        vscode.window.showInformationMessage('[DevShield] Key: ' + API_KEY.slice(0, 8) + '... | Files: ' +
            (keys.join(', ') || 'none') + ' | Issues: ' + total);
    });
    // ── DAST ─────────────────────────────────────────────────────────────────
    loadDastState(ctx);
    const dastProvider = new DastProvider(ctx);
    vscode.window.registerTreeDataProvider('devshieldDast', dastProvider);
    // Refresh so it shows scans if any exist
    dastProvider.refresh();
    ctx.subscriptions.push(vscode.commands.registerCommand('devshield.runDast', () => __awaiter(this, void 0, void 0, function* () {
        var _a;
        const input = yield vscode.window.showInputBox({
            title: 'DevShield DAST Scan',
            prompt: 'Enter the URL of your running application',
            placeHolder: 'http://localhost:3000',
            ignoreFocusOut: true,
            validateInput: v => {
                if (!v.trim()) {
                    return 'URL cannot be empty';
                }
                try {
                    new URL(v.trim());
                    return null;
                }
                catch (_a) {
                    return 'Enter a valid URL';
                }
            },
        });
        if (!input) {
            return;
        }
        const targetUrl = input.trim();
        // Create a new scan entry with unique ID
        const scanId = 'scan_' + Date.now() + '_' + Math.random().toString(36).slice(2, 9);
        const scan = {
            id: scanId,
            status: 'scanning',
            url: targetUrl,
            startTime: Date.now(),
        };
        dastScans.set(scanId, scan);
        dastProvider.refresh();
        vscode.window.setStatusBarMessage('[DevShield] DAST scanning ' + targetUrl + '...', 0);
        try {
            const res = yield axios_1.default.post(apiBase() + '/dast', { target_url: targetUrl }, { headers: apiHeaders(), responseType: 'arraybuffer', timeout: 10 * 60 * 1000 });
            const rawText = new TextDecoder('utf-8').decode(new Uint8Array(res.data));
            if (rawText.trimStart().startsWith('{')) {
                try {
                    const p = JSON.parse(rawText);
                    if (p.detail || p.error) {
                        throw new Error(String(p.detail || p.error));
                    }
                }
                catch (pe) {
                    if (pe.message !== rawText) {
                        throw pe;
                    }
                }
            }
            const rDir = getReportDir(ctx);
            fs.mkdirSync(rDir, { recursive: true });
            const rFile = path.join(rDir, 'dast_report_' + Date.now() + '.html');
            fs.writeFileSync(rFile, rawText, 'utf-8');
            // Keep only 5 most recent reports — delete oldest when 6th is added
            cleanupOldReports(rDir, 5);
            // Update scan status to done
            scan.status = 'done';
            scan.reportPath = rFile;
            dastScans.set(scanId, scan);
            saveDastState(ctx);
            dastProvider.refresh();
            vscode.window.setStatusBarMessage('[DevShield] DAST scan complete', 5000);
            const action = yield vscode.window.showInformationMessage('DAST scan of ' + targetUrl + ' complete!', 'Open Report', 'Dismiss');
            if (action === 'Open Report') {
                vscode.env.openExternal(vscode.Uri.file(rFile));
            }
        }
        catch (err) {
            const status = (_a = err === null || err === void 0 ? void 0 : err.response) === null || _a === void 0 ? void 0 : _a.status;
            let msg = String((err === null || err === void 0 ? void 0 : err.message) || 'Unknown error');
            if (status === 503) {
                msg = 'Server busy — too many scans running. Try again in a few minutes.';
            }
            else if (status === 401) {
                msg = 'Auth failed — check your API key.';
            }
            // Update scan status to error
            scan.status = 'error';
            scan.message = msg;
            dastScans.set(scanId, scan);
            saveDastState(ctx);
            dastProvider.refresh();
            vscode.window.setStatusBarMessage('[DevShield] DAST failed', 5000);
            vscode.window.showErrorMessage('[DevShield] DAST failed: ' + msg);
        }
    })));
    vscode.commands.registerCommand('devshield.openDastReport', (scanId) => {
        const scan = dastScans.get(scanId);
        if (scan && scan.status === 'done' && scan.reportPath) {
            vscode.env.openExternal(vscode.Uri.file(scan.reportPath));
        }
    });
    vscode.commands.registerCommand('devshield.retryDastScan', (url) => __awaiter(this, void 0, void 0, function* () {
        // Remove the failed scan
        for (const [id, scan] of dastScans) {
            if (scan.url === url && scan.status === 'error') {
                dastScans.delete(id);
                break;
            }
        }
        // Run new scan with the same URL
        yield vscode.commands.executeCommand('devshield.runDast');
    }));
    vscode.commands.registerCommand('devshield.deleteDastScan', (scanId) => {
        dastScans.delete(scanId);
        saveDastState(ctx);
        dastProvider.refresh();
        vscode.window.setStatusBarMessage('[DevShield] Scan removed', 2000);
    });
    // ── On deactivate: clear all panels and state ──────────────────────────────
    ctx.subscriptions.push({
        dispose() {
            vulnerabilitiesMap = {};
            dastScans.clear();
            // Clear all decorations from visible editors
            vscode.window.visibleTextEditors.forEach(ed => {
                ed.setDecorations(decHigh, []);
                ed.setDecorations(decMedium, []);
                ed.setDecorations(decLow, []);
            });
            console.log('[DevShield] Cleared all panels on deactivation');
        }
    });
}
function deactivate() { }
