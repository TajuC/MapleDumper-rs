function ensureEditor() {
  if (monacoEditor) {
    monacoEditor.layout();
    return;
  }
  if (monacoLoading) return;
  monacoLoading = true;
  $("editor-host").innerHTML = `<div style="padding:18px;color:#64748b">${esc(t("ed.loading"))}</div>`;
  require.config({ paths: { vs: "vendor/vs" } });
  require(["vs/editor/editor.main"], () => {
    monaco.languages.register({ id: "maplepat" });
    monaco.languages.setMonarchTokensProvider("maplepat", {
      tokenizer: {
        root: [
          [/\[[^\]]*\]/, "type"],
          [/[;#].*$/, "comment"],
          [/\b([A-Za-z_]\w*?)(_PTR|_CALL|_OFF|_HDR)(?=\s*[:=])/, ["identifier", "tag"]],
          [/\b[A-Za-z_]\w*(?=\s*[:=])/, "identifier"],
          [/\?\?|\?/, "keyword"],
          [/\b0x[0-9A-Fa-f]{1,2}\b/, "number"],
          [/\b[0-9A-Fa-f]{2}\b/, "number"],
          [/[:=,]/, "operator"],
        ],
      },
    });
    monaco.editor.defineTheme("mapledumper", {
      base: "vs-dark",
      inherit: true,
      rules: [
        { token: "comment", foreground: "6e7681", fontStyle: "italic" },
        { token: "type", foreground: "ffa657", fontStyle: "bold" },
        { token: "identifier", foreground: "79c0ff" },
        { token: "tag", foreground: "d2a8ff", fontStyle: "bold" },
        { token: "number", foreground: "7ee787" },
        { token: "keyword", foreground: "f778ba" },
        { token: "operator", foreground: "8b949e" },
      ],
      colors: {
        "editor.background": "#0d121b",
        "editor.foreground": "#e6edf3",
        "editorLineNumber.foreground": "#39414f",
        "editorLineNumber.activeForeground": "#9aa6b6",
        "editor.lineHighlightBackground": "#161d2a",
        "editor.lineHighlightBorder": "#00000000",
        "editor.selectionBackground": "#2d4f7c80",
        "editor.inactiveSelectionBackground": "#2d4f7c40",
        "editorCursor.foreground": "#6cb6ff",
        "editorIndentGuide.background": "#1b2330",
        "editorIndentGuide.activeBackground": "#2d3748",
        "editorBracketMatch.background": "#3b82f633",
        "editorBracketMatch.border": "#3b82f6",
        "editorGutter.background": "#0d121b",
        "editorWidget.background": "#11161f",
        "editorWidget.border": "#232c39",
        "scrollbarSlider.background": "#232c3988",
        "scrollbarSlider.hoverBackground": "#2e3a4a",
        "scrollbarSlider.activeBackground": "#3a4658",
      },
    });
    $("editor-host").innerHTML = "";
    monacoEditor = monaco.editor.create($("editor-host"), {
      value: state.patternText,
      language: "maplepat",
      theme: "mapledumper",
      fontFamily: "Cascadia Code, JetBrains Mono, Consolas, monospace",
      fontLigatures: true,
      fontSize: 14,
      lineHeight: 22,
      letterSpacing: 0.3,
      minimap: { enabled: false },
      automaticLayout: true,
      scrollBeyondLastLine: false,
      padding: { top: 16, bottom: 16 },
      renderLineHighlight: "all",
      cursorBlinking: "smooth",
      cursorSmoothCaretAnimation: "on",
      smoothScrolling: true,
      roundedSelection: true,
      bracketPairColorization: { enabled: true },
      scrollbar: { verticalScrollbarSize: 11, horizontalScrollbarSize: 11 },
    });
    monacoEditor.onDidChangeModelContent(() => (state.patternText = monacoEditor.getValue()));
    monacoLoading = false;
  });
}

function syncEditor() {
  if (monacoEditor && monacoEditor.getValue() !== state.patternText) monacoEditor.setValue(state.patternText);
}
