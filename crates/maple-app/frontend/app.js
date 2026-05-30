const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

const I18N = {
  en: {
    "nav.workspace": "Workspace", "nav.patterns": "Patterns", "nav.editor": "Editor", "nav.output": "Output", "nav.settings": "Settings",
    "engine.label": "Engine", "engine.offline": "Engine offline", "engine.ready": "Ready",
    "conn.idle": "Idle", "conn.waiting": "Waiting", "conn.scanning": "Scanning", "conn.attached": "Attached", "conn.error": "Error", "conn.cancelled": "Cancelled",
    "ws.targetProcess": "Target process", "ws.windowClass": "Window class", "ws.module": "Module", "ws.patternSource": "Pattern source",
    "ws.startScan": "Start Scan", "ws.stop": "Stop", "ws.arch64": "64-bit", "ws.arch32": "32-bit",
    "ws.waitTarget": "Wait for target", "ws.findByClass": "Find by window class", "ws.codeOnly": "Code regions only",
    "ws.timeout": "Timeout", "ws.seconds": "s", "ws.export": "Export", "ws.exportHeader": "C++ header (offsets.h)", "ws.exportCe": "Cheat Engine table", "ws.exportTxt": "Plain text",
    "ws.results": "Results", "ws.resultsSub": "Pattern matches grouped by category", "ws.tabAll": "All", "ws.searchResults": "Search by name or address…",
    "ws.empty": "No scan yet. Set a target and click Start Scan.", "ws.emptyFilter": "No rows match this filter.",
    "ws.builtinSamples": "Built-in samples", "ws.windowClassPh": "Window class name", "ws.loadFileTitle": "Load a pattern file",
    "col.name": "Name", "col.address": "Address (RVA)", "col.signature": "Signature", "col.status": "Status", "col.type": "Type", "col.hits": "Hits", "col.category": "Category", "col.note": "Note",
    "insp.noSelection": "No selection", "insp.selectRow": "Select a row to inspect it.", "insp.hint": "Run a scan, then select a result to inspect its metadata and hit count.",
    "insp.rva": "RVA", "insp.absolute": "Absolute", "insp.signature": "Signature", "insp.type": "Type", "insp.category": "Category", "insp.module": "Module", "insp.hitCount": "Hit count", "insp.notes": "Notes", "insp.noNotes": "No notes", "insp.copyAddress": "Copy address", "insp.displacement": "displacement",
    "foot.idle": "Idle", "foot.idleSub": "Configure a target to begin.", "foot.waiting": "Waiting for target…", "foot.waitingSub": "Will attach the moment it appears.",
    "foot.scanning": "Scanning patterns…", "foot.scanningSub": "Reading committed memory regions.", "foot.complete": "Scan complete",
    "foot.completeSub": "{found} of {total} resolved · {mb} MB @ {gbs} GB/s · attach {attach} ms", "foot.failed": "Scan failed", "foot.cancelled": "Cancelled", "foot.cancelledSub": "The scan was stopped.",
    "foot.patternsLoaded": "Patterns loaded", "foot.found": "Found", "foot.unresolved": "Unresolved", "foot.scanTime": "Scan time", "foot.module": "Module", "foot.openEditor": "Open editor",
    "status.found": "Found", "status.unresolved": "Unresolved", "status.notFound": "Not Found",
    "type.pointer": "Pointer", "type.function": "Function", "type.offset": "Offset", "type.header": "Header", "type.address": "Address",
    "pat.title": "Patterns", "pat.count": "{n} patterns", "pat.countOne": "1 pattern", "pat.add": "+ Add", "pat.load": "Load", "pat.save": "Save", "pat.filter": "Filter patterns…", "pat.allCategories": "All categories", "pat.empty": "No patterns. Use + Add or load a file.", "pat.edit": "edit", "pat.del": "del",
    "res.count": "{n} results", "res.countOne": "1 result",
    "ed.title": "Editor", "ed.sub": "Syntax-highlighted pattern editor", "ed.load": "Load", "ed.save": "Save", "ed.apply": "Apply", "ed.loading": "loading editor…",
    "out.title": "Output", "out.nothing": "No export yet", "out.copy": "Copy", "out.save": "Save", "out.default": "Run a scan, then export from the Workspace toolbar.", "out.label": "{name} · {n} lines",
    "set.title": "Settings", "set.sub": "Privacy mask and display options", "set.maskTitle": "Privacy mask",
    "set.maskDesc": "Choose what the eye button in the title bar blurs for screenshots. It applies across every tab, and never changes your data; only the on-screen display is hidden.",
    "set.sig": "Signatures", "set.sigDesc": "AOB byte patterns in tables, the inspector, and the edit dialog",
    "set.name": "Pattern names", "set.nameDesc": "Symbol names everywhere they appear", "set.addr": "Addresses", "set.addrDesc": "Resolved RVA and absolute addresses",
    "set.cat": "Categories", "set.catDesc": "Category labels", "set.note": "Notes", "set.noteDesc": "Per-pattern notes", "set.editor": "Editor", "set.editorDesc": "Blur the entire code editor", "set.output": "Output", "set.outputDesc": "Blur generated headers, tables, and reports",
    "set.langTitle": "Language", "set.langDesc": "Display language for the interface.",
    "modal.add": "Add pattern", "modal.edit": "Edit pattern", "modal.name": "Name", "modal.category": "Category", "modal.signature": "Signature (AOB)", "modal.note": "Note", "modal.cancel": "Cancel", "modal.save": "Save", "modal.phNote": "Optional",
    "toast.enterTarget": "Enter a target process or window class.", "toast.addressCopied": "Address copied", "toast.copied": "Copied to clipboard", "toast.saved": "Saved to {path}", "toast.loadedN": "Loaded {n} patterns", "toast.loaded": "Loaded", "toast.deleted": "Pattern deleted", "toast.added": "Pattern added", "toast.updated": "Pattern updated", "toast.nameAobRequired": "Name and signature are required.", "toast.appliedN": "Applied {n} patterns",
    "mask.on": "Show everything", "mask.off": "Mask for screenshots", "win.min": "Minimize", "win.max": "Maximize", "win.close": "Close",
  },
  ja: {
    "nav.workspace": "ワークスペース", "nav.patterns": "パターン", "nav.editor": "エディタ", "nav.output": "出力", "nav.settings": "設定",
    "engine.label": "エンジン", "engine.offline": "エンジンオフライン", "engine.ready": "準備完了",
    "conn.idle": "アイドル", "conn.waiting": "待機中", "conn.scanning": "スキャン中", "conn.attached": "アタッチ済み", "conn.error": "エラー", "conn.cancelled": "キャンセル済み",
    "ws.targetProcess": "対象プロセス", "ws.windowClass": "ウィンドウクラス", "ws.module": "モジュール", "ws.patternSource": "パターンソース",
    "ws.startScan": "スキャン開始", "ws.stop": "停止", "ws.arch64": "64ビット", "ws.arch32": "32ビット",
    "ws.waitTarget": "対象を待機", "ws.findByClass": "ウィンドウクラスで検索", "ws.codeOnly": "コード領域のみ",
    "ws.timeout": "タイムアウト", "ws.seconds": "秒", "ws.export": "エクスポート", "ws.exportHeader": "C++ ヘッダー (offsets.h)", "ws.exportCe": "Cheat Engine テーブル", "ws.exportTxt": "プレーンテキスト",
    "ws.results": "結果", "ws.resultsSub": "カテゴリ別のパターン一致", "ws.tabAll": "すべて", "ws.searchResults": "名前またはアドレスで検索…",
    "ws.empty": "まだスキャンしていません。対象を設定して「スキャン開始」をクリックしてください。", "ws.emptyFilter": "このフィルターに一致する行はありません。",
    "ws.builtinSamples": "組み込みサンプル", "ws.windowClassPh": "ウィンドウクラス名", "ws.loadFileTitle": "パターンファイルを読み込む",
    "col.name": "名前", "col.address": "アドレス (RVA)", "col.signature": "シグネチャ", "col.status": "ステータス", "col.type": "種類", "col.hits": "ヒット", "col.category": "カテゴリ", "col.note": "メモ",
    "insp.noSelection": "選択なし", "insp.selectRow": "行を選択して詳細を表示します。", "insp.hint": "スキャンを実行し、結果を選択するとメタデータとヒット数を確認できます。",
    "insp.rva": "RVA", "insp.absolute": "絶対アドレス", "insp.signature": "シグネチャ", "insp.type": "種類", "insp.category": "カテゴリ", "insp.module": "モジュール", "insp.hitCount": "ヒット数", "insp.notes": "メモ", "insp.noNotes": "メモなし", "insp.copyAddress": "アドレスをコピー", "insp.displacement": "変位",
    "foot.idle": "アイドル", "foot.idleSub": "対象を設定して開始してください。", "foot.waiting": "対象を待機中…", "foot.waitingSub": "起動した瞬間にアタッチします。",
    "foot.scanning": "パターンをスキャン中…", "foot.scanningSub": "コミット済みメモリ領域を読み取り中。", "foot.complete": "スキャン完了",
    "foot.completeSub": "{total} 件中 {found} 件を解決 · {mb} MB @ {gbs} GB/s · アタッチ {attach} ms", "foot.failed": "スキャン失敗", "foot.cancelled": "キャンセル", "foot.cancelledSub": "スキャンを停止しました。",
    "foot.patternsLoaded": "読み込み済みパターン", "foot.found": "検出", "foot.unresolved": "未解決", "foot.scanTime": "スキャン時間", "foot.module": "モジュール", "foot.openEditor": "エディタを開く",
    "status.found": "検出", "status.unresolved": "未解決", "status.notFound": "未検出",
    "type.pointer": "ポインタ", "type.function": "関数", "type.offset": "オフセット", "type.header": "ヘッダー", "type.address": "アドレス",
    "pat.title": "パターン", "pat.count": "{n} 件のパターン", "pat.countOne": "1 件のパターン", "pat.add": "+ 追加", "pat.load": "読み込み", "pat.save": "保存", "pat.filter": "パターンをフィルター…", "pat.allCategories": "すべてのカテゴリ", "pat.empty": "パターンがありません。「+ 追加」またはファイルを読み込んでください。", "pat.edit": "編集", "pat.del": "削除",
    "res.count": "{n} 件の結果", "res.countOne": "1 件の結果",
    "ed.title": "エディタ", "ed.sub": "構文ハイライト付きパターンエディタ", "ed.load": "読み込み", "ed.save": "保存", "ed.apply": "適用", "ed.loading": "エディタを読み込み中…",
    "out.title": "出力", "out.nothing": "まだエクスポートがありません", "out.copy": "コピー", "out.save": "保存", "out.default": "スキャンを実行し、ワークスペースのツールバーからエクスポートしてください。", "out.label": "{name} · {n} 行",
    "set.title": "設定", "set.sub": "プライバシーマスクと表示オプション", "set.maskTitle": "プライバシーマスク",
    "set.maskDesc": "タイトルバーの目アイコンがスクリーンショット用にぼかす項目を選択します。すべてのタブに適用され、データは変更されず、画面表示のみが隠されます。",
    "set.sig": "シグネチャ", "set.sigDesc": "テーブル、インスペクター、編集ダイアログの AOB バイトパターン",
    "set.name": "パターン名", "set.nameDesc": "表示されるすべてのシンボル名", "set.addr": "アドレス", "set.addrDesc": "解決された RVA と絶対アドレス",
    "set.cat": "カテゴリ", "set.catDesc": "カテゴリラベル", "set.note": "メモ", "set.noteDesc": "パターンごとのメモ", "set.editor": "エディタ", "set.editorDesc": "コードエディタ全体をぼかす", "set.output": "出力", "set.outputDesc": "生成されたヘッダー、テーブル、レポートをぼかす",
    "set.langTitle": "言語", "set.langDesc": "インターフェースの表示言語。",
    "modal.add": "パターンを追加", "modal.edit": "パターンを編集", "modal.name": "名前", "modal.category": "カテゴリ", "modal.signature": "シグネチャ (AOB)", "modal.note": "メモ", "modal.cancel": "キャンセル", "modal.save": "保存", "modal.phNote": "任意",
    "toast.enterTarget": "対象プロセスまたはウィンドウクラスを入力してください。", "toast.addressCopied": "アドレスをコピーしました", "toast.copied": "クリップボードにコピーしました", "toast.saved": "{path} に保存しました", "toast.loadedN": "{n} 件のパターンを読み込みました", "toast.loaded": "読み込みました", "toast.deleted": "パターンを削除しました", "toast.added": "パターンを追加しました", "toast.updated": "パターンを更新しました", "toast.nameAobRequired": "名前とシグネチャは必須です。", "toast.appliedN": "{n} 件のパターンを適用しました",
    "mask.on": "すべて表示", "mask.off": "スクリーンショット用にマスク", "win.min": "最小化", "win.max": "最大化", "win.close": "閉じる",
  },
  zh: {
    "nav.workspace": "工作区", "nav.patterns": "模式", "nav.editor": "编辑器", "nav.output": "输出", "nav.settings": "设置",
    "engine.label": "引擎", "engine.offline": "引擎离线", "engine.ready": "就绪",
    "conn.idle": "空闲", "conn.waiting": "等待中", "conn.scanning": "扫描中", "conn.attached": "已附加", "conn.error": "错误", "conn.cancelled": "已取消",
    "ws.targetProcess": "目标进程", "ws.windowClass": "窗口类", "ws.module": "模块", "ws.patternSource": "模式来源",
    "ws.startScan": "开始扫描", "ws.stop": "停止", "ws.arch64": "64 位", "ws.arch32": "32 位",
    "ws.waitTarget": "等待目标", "ws.findByClass": "按窗口类查找", "ws.codeOnly": "仅代码区域",
    "ws.timeout": "超时", "ws.seconds": "秒", "ws.export": "导出", "ws.exportHeader": "C++ 头文件 (offsets.h)", "ws.exportCe": "Cheat Engine 表", "ws.exportTxt": "纯文本",
    "ws.results": "结果", "ws.resultsSub": "按类别分组的匹配结果", "ws.tabAll": "全部", "ws.searchResults": "按名称或地址搜索…",
    "ws.empty": "尚未扫描。设置目标后点击开始扫描。", "ws.emptyFilter": "没有符合此筛选的行。",
    "ws.builtinSamples": "内置示例", "ws.windowClassPh": "窗口类名", "ws.loadFileTitle": "加载模式文件",
    "col.name": "名称", "col.address": "地址 (RVA)", "col.signature": "特征码", "col.status": "状态", "col.type": "类型", "col.hits": "命中", "col.category": "类别", "col.note": "备注",
    "insp.noSelection": "未选择", "insp.selectRow": "选择一行以查看详情。", "insp.hint": "运行扫描后，选择结果即可查看其元数据和命中次数。",
    "insp.rva": "RVA", "insp.absolute": "绝对地址", "insp.signature": "特征码", "insp.type": "类型", "insp.category": "类别", "insp.module": "模块", "insp.hitCount": "命中次数", "insp.notes": "备注", "insp.noNotes": "无备注", "insp.copyAddress": "复制地址", "insp.displacement": "偏移",
    "foot.idle": "空闲", "foot.idleSub": "配置目标以开始。", "foot.waiting": "等待目标中…", "foot.waitingSub": "一旦出现将立即附加。",
    "foot.scanning": "正在扫描模式…", "foot.scanningSub": "正在读取已提交的内存区域。", "foot.complete": "扫描完成",
    "foot.completeSub": "{total} 中 {found} 个已解析 · {mb} MB @ {gbs} GB/s · 附加 {attach} ms", "foot.failed": "扫描失败", "foot.cancelled": "已取消", "foot.cancelledSub": "扫描已停止。",
    "foot.patternsLoaded": "已加载模式", "foot.found": "已找到", "foot.unresolved": "未解析", "foot.scanTime": "扫描时间", "foot.module": "模块", "foot.openEditor": "打开编辑器",
    "status.found": "已找到", "status.unresolved": "未解析", "status.notFound": "未找到",
    "type.pointer": "指针", "type.function": "函数", "type.offset": "偏移", "type.header": "头", "type.address": "地址",
    "pat.title": "模式", "pat.count": "{n} 个模式", "pat.countOne": "1 个模式", "pat.add": "+ 添加", "pat.load": "加载", "pat.save": "保存", "pat.filter": "筛选模式…", "pat.allCategories": "所有类别", "pat.empty": "没有模式。使用 + 添加 或加载文件。", "pat.edit": "编辑", "pat.del": "删除",
    "res.count": "{n} 个结果", "res.countOne": "1 个结果",
    "ed.title": "编辑器", "ed.sub": "语法高亮的模式编辑器", "ed.load": "加载", "ed.save": "保存", "ed.apply": "应用", "ed.loading": "正在加载编辑器…",
    "out.title": "输出", "out.nothing": "尚无导出", "out.copy": "复制", "out.save": "保存", "out.default": "运行扫描后，从工作区工具栏导出。", "out.label": "{name} · {n} 行",
    "set.title": "设置", "set.sub": "隐私遮罩与显示选项", "set.maskTitle": "隐私遮罩",
    "set.maskDesc": "选择标题栏的眼睛按钮在截图时模糊哪些内容。它适用于所有标签页，不会更改你的数据，仅隐藏屏幕显示。",
    "set.sig": "特征码", "set.sigDesc": "表格、检查器和编辑对话框中的 AOB 字节模式",
    "set.name": "模式名称", "set.nameDesc": "所有出现的符号名称", "set.addr": "地址", "set.addrDesc": "解析出的 RVA 和绝对地址",
    "set.cat": "类别", "set.catDesc": "类别标签", "set.note": "备注", "set.noteDesc": "每个模式的备注", "set.editor": "编辑器", "set.editorDesc": "模糊整个代码编辑器", "set.output": "输出", "set.outputDesc": "模糊生成的头文件、表和报告",
    "set.langTitle": "语言", "set.langDesc": "界面显示语言。",
    "modal.add": "添加模式", "modal.edit": "编辑模式", "modal.name": "名称", "modal.category": "类别", "modal.signature": "特征码 (AOB)", "modal.note": "备注", "modal.cancel": "取消", "modal.save": "保存", "modal.phNote": "可选",
    "toast.enterTarget": "请输入目标进程或窗口类。", "toast.addressCopied": "已复制地址", "toast.copied": "已复制到剪贴板", "toast.saved": "已保存到 {path}", "toast.loadedN": "已加载 {n} 个模式", "toast.loaded": "已加载", "toast.deleted": "已删除模式", "toast.added": "已添加模式", "toast.updated": "已更新模式", "toast.nameAobRequired": "名称和特征码为必填项。", "toast.appliedN": "已应用 {n} 个模式",
    "mask.on": "显示全部", "mask.off": "为截图遮罩", "win.min": "最小化", "win.max": "最大化", "win.close": "关闭",
  },
  ko: {
    "nav.workspace": "작업 공간", "nav.patterns": "패턴", "nav.editor": "편집기", "nav.output": "출력", "nav.settings": "설정",
    "engine.label": "엔진", "engine.offline": "엔진 오프라인", "engine.ready": "준비됨",
    "conn.idle": "대기", "conn.waiting": "대기 중", "conn.scanning": "스캔 중", "conn.attached": "연결됨", "conn.error": "오류", "conn.cancelled": "취소됨",
    "ws.targetProcess": "대상 프로세스", "ws.windowClass": "윈도우 클래스", "ws.module": "모듈", "ws.patternSource": "패턴 소스",
    "ws.startScan": "스캔 시작", "ws.stop": "중지", "ws.arch64": "64비트", "ws.arch32": "32비트",
    "ws.waitTarget": "대상 대기", "ws.findByClass": "윈도우 클래스로 찾기", "ws.codeOnly": "코드 영역만",
    "ws.timeout": "시간 제한", "ws.seconds": "초", "ws.export": "내보내기", "ws.exportHeader": "C++ 헤더 (offsets.h)", "ws.exportCe": "Cheat Engine 테이블", "ws.exportTxt": "일반 텍스트",
    "ws.results": "결과", "ws.resultsSub": "카테고리별 패턴 일치", "ws.tabAll": "전체", "ws.searchResults": "이름 또는 주소로 검색…",
    "ws.empty": "아직 스캔하지 않았습니다. 대상을 설정하고 스캔 시작을 클릭하세요.", "ws.emptyFilter": "이 필터와 일치하는 행이 없습니다.",
    "ws.builtinSamples": "기본 제공 샘플", "ws.windowClassPh": "윈도우 클래스 이름", "ws.loadFileTitle": "패턴 파일 불러오기",
    "col.name": "이름", "col.address": "주소 (RVA)", "col.signature": "시그니처", "col.status": "상태", "col.type": "유형", "col.hits": "적중", "col.category": "카테고리", "col.note": "메모",
    "insp.noSelection": "선택 없음", "insp.selectRow": "행을 선택하면 자세히 볼 수 있습니다.", "insp.hint": "스캔을 실행한 다음 결과를 선택하면 메타데이터와 적중 횟수를 확인할 수 있습니다.",
    "insp.rva": "RVA", "insp.absolute": "절대 주소", "insp.signature": "시그니처", "insp.type": "유형", "insp.category": "카테고리", "insp.module": "모듈", "insp.hitCount": "적중 횟수", "insp.notes": "메모", "insp.noNotes": "메모 없음", "insp.copyAddress": "주소 복사", "insp.displacement": "변위",
    "foot.idle": "대기", "foot.idleSub": "시작하려면 대상을 설정하세요.", "foot.waiting": "대상 대기 중…", "foot.waitingSub": "나타나는 즉시 연결합니다.",
    "foot.scanning": "패턴 스캔 중…", "foot.scanningSub": "커밋된 메모리 영역을 읽는 중.", "foot.complete": "스캔 완료",
    "foot.completeSub": "{total}개 중 {found}개 해결 · {mb} MB @ {gbs} GB/s · 연결 {attach} ms", "foot.failed": "스캔 실패", "foot.cancelled": "취소됨", "foot.cancelledSub": "스캔이 중지되었습니다.",
    "foot.patternsLoaded": "로드된 패턴", "foot.found": "찾음", "foot.unresolved": "미해결", "foot.scanTime": "스캔 시간", "foot.module": "모듈", "foot.openEditor": "편집기 열기",
    "status.found": "찾음", "status.unresolved": "미해결", "status.notFound": "찾지 못함",
    "type.pointer": "포인터", "type.function": "함수", "type.offset": "오프셋", "type.header": "헤더", "type.address": "주소",
    "pat.title": "패턴", "pat.count": "패턴 {n}개", "pat.countOne": "패턴 1개", "pat.add": "+ 추가", "pat.load": "불러오기", "pat.save": "저장", "pat.filter": "패턴 필터…", "pat.allCategories": "모든 카테고리", "pat.empty": "패턴이 없습니다. + 추가를 사용하거나 파일을 불러오세요.", "pat.edit": "편집", "pat.del": "삭제",
    "res.count": "결과 {n}개", "res.countOne": "결과 1개",
    "ed.title": "편집기", "ed.sub": "구문 강조 패턴 편집기", "ed.load": "불러오기", "ed.save": "저장", "ed.apply": "적용", "ed.loading": "편집기 로딩 중…",
    "out.title": "출력", "out.nothing": "아직 내보낸 항목 없음", "out.copy": "복사", "out.save": "저장", "out.default": "스캔을 실행한 다음 작업 공간 도구 모음에서 내보내세요.", "out.label": "{name} · {n}줄",
    "set.title": "설정", "set.sub": "개인정보 마스크 및 표시 옵션", "set.maskTitle": "개인정보 마스크",
    "set.maskDesc": "제목 표시줄의 눈 버튼이 스크린샷을 위해 흐리게 처리할 항목을 선택하세요. 모든 탭에 적용되며 데이터를 변경하지 않고 화면 표시만 가립니다.",
    "set.sig": "시그니처", "set.sigDesc": "테이블, 인스펙터, 편집 대화상자의 AOB 바이트 패턴",
    "set.name": "패턴 이름", "set.nameDesc": "표시되는 모든 심볼 이름", "set.addr": "주소", "set.addrDesc": "해결된 RVA 및 절대 주소",
    "set.cat": "카테고리", "set.catDesc": "카테고리 레이블", "set.note": "메모", "set.noteDesc": "패턴별 메모", "set.editor": "편집기", "set.editorDesc": "전체 코드 편집기 흐리게", "set.output": "출력", "set.outputDesc": "생성된 헤더, 테이블, 보고서 흐리게",
    "set.langTitle": "언어", "set.langDesc": "인터페이스 표시 언어.",
    "modal.add": "패턴 추가", "modal.edit": "패턴 편집", "modal.name": "이름", "modal.category": "카테고리", "modal.signature": "시그니처 (AOB)", "modal.note": "메모", "modal.cancel": "취소", "modal.save": "저장", "modal.phNote": "선택 사항",
    "toast.enterTarget": "대상 프로세스 또는 윈도우 클래스를 입력하세요.", "toast.addressCopied": "주소를 복사했습니다", "toast.copied": "클립보드에 복사했습니다", "toast.saved": "{path}에 저장했습니다", "toast.loadedN": "패턴 {n}개를 불러왔습니다", "toast.loaded": "불러왔습니다", "toast.deleted": "패턴을 삭제했습니다", "toast.added": "패턴을 추가했습니다", "toast.updated": "패턴을 업데이트했습니다", "toast.nameAobRequired": "이름과 시그니처는 필수입니다.", "toast.appliedN": "패턴 {n}개를 적용했습니다",
    "mask.on": "모두 표시", "mask.off": "스크린샷용 마스크", "win.min": "최소화", "win.max": "최대화", "win.close": "닫기",
  },
  he: {
    "nav.workspace": "סביבת עבודה", "nav.patterns": "תבניות", "nav.editor": "עורך", "nav.output": "פלט", "nav.settings": "הגדרות",
    "engine.label": "מנוע", "engine.offline": "המנוע במצב לא מקוון", "engine.ready": "מוכן",
    "conn.idle": "במנוחה", "conn.waiting": "ממתין", "conn.scanning": "סורק", "conn.attached": "מחובר", "conn.error": "שגיאה", "conn.cancelled": "בוטל",
    "ws.targetProcess": "תהליך יעד", "ws.windowClass": "מחלקת חלון", "ws.module": "מודול", "ws.patternSource": "מקור תבניות",
    "ws.startScan": "התחל סריקה", "ws.stop": "עצור", "ws.arch64": "64 סיביות", "ws.arch32": "32 סיביות",
    "ws.waitTarget": "המתן ליעד", "ws.findByClass": "מצא לפי מחלקת חלון", "ws.codeOnly": "אזורי קוד בלבד",
    "ws.timeout": "זמן קצוב", "ws.seconds": "שנ׳", "ws.export": "ייצוא", "ws.exportHeader": "כותרת C++ (offsets.h)", "ws.exportCe": "טבלת Cheat Engine", "ws.exportTxt": "טקסט רגיל",
    "ws.results": "תוצאות", "ws.resultsSub": "התאמות תבנית מקובצות לפי קטגוריה", "ws.tabAll": "הכול", "ws.searchResults": "חיפוש לפי שם או כתובת…",
    "ws.empty": "עדיין לא בוצעה סריקה. הגדר יעד ולחץ על התחל סריקה.", "ws.emptyFilter": "אין שורות התואמות למסנן זה.",
    "ws.builtinSamples": "דוגמאות מובנות", "ws.windowClassPh": "שם מחלקת חלון", "ws.loadFileTitle": "טען קובץ תבניות",
    "col.name": "שם", "col.address": "כתובת (RVA)", "col.signature": "חתימה", "col.status": "סטטוס", "col.type": "סוג", "col.hits": "התאמות", "col.category": "קטגוריה", "col.note": "הערה",
    "insp.noSelection": "אין בחירה", "insp.selectRow": "בחר שורה כדי לבדוק אותה.", "insp.hint": "הרץ סריקה ובחר תוצאה כדי לראות את המטא-נתונים ומספר ההתאמות שלה.",
    "insp.rva": "RVA", "insp.absolute": "כתובת מוחלטת", "insp.signature": "חתימה", "insp.type": "סוג", "insp.category": "קטגוריה", "insp.module": "מודול", "insp.hitCount": "מספר התאמות", "insp.notes": "הערות", "insp.noNotes": "אין הערות", "insp.copyAddress": "העתק כתובת", "insp.displacement": "היסט",
    "foot.idle": "במנוחה", "foot.idleSub": "הגדר יעד כדי להתחיל.", "foot.waiting": "ממתין ליעד…", "foot.waitingSub": "יתחבר ברגע שהיעד יופיע.",
    "foot.scanning": "סורק תבניות…", "foot.scanningSub": "קורא אזורי זיכרון מחויבים.", "foot.complete": "הסריקה הושלמה",
    "foot.completeSub": "{found} מתוך {total} נפתרו · {mb} MB @ {gbs} GB/s · חיבור {attach} ms", "foot.failed": "הסריקה נכשלה", "foot.cancelled": "בוטל", "foot.cancelledSub": "הסריקה הופסקה.",
    "foot.patternsLoaded": "תבניות שנטענו", "foot.found": "נמצאו", "foot.unresolved": "לא נפתרו", "foot.scanTime": "זמן סריקה", "foot.module": "מודול", "foot.openEditor": "פתח עורך",
    "status.found": "נמצא", "status.unresolved": "לא נפתר", "status.notFound": "לא נמצא",
    "type.pointer": "מצביע", "type.function": "פונקציה", "type.offset": "היסט", "type.header": "כותרת", "type.address": "כתובת",
    "pat.title": "תבניות", "pat.count": "{n} תבניות", "pat.countOne": "תבנית אחת", "pat.add": "+ הוסף", "pat.load": "טען", "pat.save": "שמור", "pat.filter": "סנן תבניות…", "pat.allCategories": "כל הקטגוריות", "pat.empty": "אין תבניות. השתמש ב-+ הוסף או טען קובץ.", "pat.edit": "ערוך", "pat.del": "מחק",
    "res.count": "{n} תוצאות", "res.countOne": "תוצאה אחת",
    "ed.title": "עורך", "ed.sub": "עורך תבניות עם הדגשת תחביר", "ed.load": "טען", "ed.save": "שמור", "ed.apply": "החל", "ed.loading": "טוען עורך…",
    "out.title": "פלט", "out.nothing": "עדיין אין ייצוא", "out.copy": "העתק", "out.save": "שמור", "out.default": "הרץ סריקה ולאחר מכן ייצא מסרגל הכלים של סביבת העבודה.", "out.label": "{name} · {n} שורות",
    "set.title": "הגדרות", "set.sub": "מסכת פרטיות ואפשרויות תצוגה", "set.maskTitle": "מסכת פרטיות",
    "set.maskDesc": "בחר מה כפתור העין בשורת הכותרת יטשטש עבור צילומי מסך. חל על כל הלשוניות, אינו משנה את הנתונים ומסתיר רק את התצוגה על המסך.",
    "set.sig": "חתימות", "set.sigDesc": "תבניות בתים (AOB) בטבלאות, במפקח ובתיבת העריכה",
    "set.name": "שמות תבניות", "set.nameDesc": "שמות סמלים בכל מקום שהם מופיעים", "set.addr": "כתובות", "set.addrDesc": "כתובות RVA ומוחלטות שנפתרו",
    "set.cat": "קטגוריות", "set.catDesc": "תוויות קטגוריה", "set.note": "הערות", "set.noteDesc": "הערות לכל תבנית", "set.editor": "עורך", "set.editorDesc": "טשטש את כל עורך הקוד", "set.output": "פלט", "set.outputDesc": "טשטש כותרות, טבלאות ודוחות שנוצרו",
    "set.langTitle": "שפה", "set.langDesc": "שפת התצוגה של הממשק.",
    "modal.add": "הוסף תבנית", "modal.edit": "ערוך תבנית", "modal.name": "שם", "modal.category": "קטגוריה", "modal.signature": "חתימה (AOB)", "modal.note": "הערה", "modal.cancel": "ביטול", "modal.save": "שמור", "modal.phNote": "אופציונלי",
    "toast.enterTarget": "הזן תהליך יעד או מחלקת חלון.", "toast.addressCopied": "הכתובת הועתקה", "toast.copied": "הועתק ללוח", "toast.saved": "נשמר אל {path}", "toast.loadedN": "נטענו {n} תבניות", "toast.loaded": "נטען", "toast.deleted": "התבנית נמחקה", "toast.added": "התבנית נוספה", "toast.updated": "התבנית עודכנה", "toast.nameAobRequired": "שם וחתימה הם שדות חובה.", "toast.appliedN": "הוחלו {n} תבניות",
    "mask.on": "הצג הכול", "mask.off": "הסתר לצילומי מסך", "win.min": "מזער", "win.max": "הגדל", "win.close": "סגור",
  },
};
const RTL = new Set(["he"]);
const LANGS = [
  { code: "en", label: "English" },
  { code: "ja", label: "日本語" },
  { code: "zh", label: "中文" },
  { code: "ko", label: "한국어" },
  { code: "he", label: "עברית" },
];
let LANG = "en";
try {
  const savedLang = localStorage.getItem("lang");
  if (savedLang && I18N[savedLang]) LANG = savedLang;
} catch {
}
let onLangChange = null;
const DIFF_I18N = {
  en: {
    "nav.diff": "Diff",
    "diff.title": "Diff",
    "diff.sub": "Compare two saved dumps",
    "diff.loadA": "Load A (old)",
    "diff.loadB": "Load B (new)",
    "diff.compare": "Compare",
    "diff.empty": "Load two dumps (A = old, B = new) and click Compare.",
    "diff.noChanges": "No differences.",
    "diff.needBoth": "Load both A and B first.",
    "diff.unchanged": "unchanged",
    "diff.new": "new",
    "diff.moved": "moved",
    "diff.removed": "removed",
    "diff.changed": "changed",
    "diff.same": "same",
    "diff.colChange": "Change",
    "diff.colOld": "Old",
    "diff.colNew": "New",
  },
  ja: {
    "nav.diff": "差分",
    "diff.title": "差分",
    "diff.sub": "保存した2つのダンプを比較します",
    "diff.loadA": "A を読み込み（旧）",
    "diff.loadB": "B を読み込み（新）",
    "diff.compare": "比較",
    "diff.empty": "2つのダンプ（A = 旧、B = 新）を読み込んで「比較」を押してください。",
    "diff.noChanges": "差分はありません。",
    "diff.needBoth": "先に A と B の両方を読み込んでください。",
    "diff.unchanged": "変更なし",
    "diff.new": "新規",
    "diff.moved": "移動",
    "diff.removed": "削除",
    "diff.changed": "変更あり",
    "diff.same": "同一",
    "diff.colChange": "種別",
    "diff.colOld": "旧",
    "diff.colNew": "新",
  },
  zh: {
    "nav.diff": "差异",
    "diff.title": "差异",
    "diff.sub": "比较两个已保存的转储",
    "diff.loadA": "加载 A（旧）",
    "diff.loadB": "加载 B（新）",
    "diff.compare": "比较",
    "diff.empty": "加载两个转储（A = 旧，B = 新），然后点击“比较”。",
    "diff.noChanges": "没有差异。",
    "diff.needBoth": "请先加载 A 和 B。",
    "diff.unchanged": "未变",
    "diff.new": "新增",
    "diff.moved": "移动",
    "diff.removed": "移除",
    "diff.changed": "已更改",
    "diff.same": "相同",
    "diff.colChange": "变更",
    "diff.colOld": "旧",
    "diff.colNew": "新",
  },
  ko: {
    "nav.diff": "비교",
    "diff.title": "비교",
    "diff.sub": "저장된 두 덤프를 비교합니다",
    "diff.loadA": "A 불러오기 (이전)",
    "diff.loadB": "B 불러오기 (새로운)",
    "diff.compare": "비교",
    "diff.empty": "두 덤프(A = 이전, B = 새로운)를 불러온 후 비교를 클릭하세요.",
    "diff.noChanges": "차이가 없습니다.",
    "diff.needBoth": "먼저 A와 B를 모두 불러오세요.",
    "diff.unchanged": "변경 없음",
    "diff.new": "신규",
    "diff.moved": "이동",
    "diff.removed": "제거",
    "diff.changed": "변경됨",
    "diff.same": "동일",
    "diff.colChange": "변경",
    "diff.colOld": "이전",
    "diff.colNew": "새로운",
  },
  he: {
    "nav.diff": "השוואה",
    "diff.title": "השוואה",
    "diff.sub": "השוואת שני קובצי dump שמורים",
    "diff.loadA": "טען A (ישן)",
    "diff.loadB": "טען B (חדש)",
    "diff.compare": "השווה",
    "diff.empty": "טען שני קובצי dump (A = ישן, B = חדש) ולחץ על השווה.",
    "diff.noChanges": "אין הבדלים.",
    "diff.needBoth": "טען תחילה גם את A וגם את B.",
    "diff.unchanged": "ללא שינוי",
    "diff.new": "חדש",
    "diff.moved": "הוזז",
    "diff.removed": "הוסר",
    "diff.changed": "השתנה",
    "diff.same": "זהה",
    "diff.colChange": "שינוי",
    "diff.colOld": "ישן",
    "diff.colNew": "חדש",
  },
};
Object.keys(DIFF_I18N).forEach((lang) => Object.assign(I18N[lang], DIFF_I18N[lang]));

const HIST_I18N = {
  en: {
    "nav.history": "History",
    "hist.title": "History",
    "hist.sub": "Every scan, grouped by version",
    "hist.refresh": "Refresh",
    "hist.compare": "Compare A ↔ B",
    "hist.clear": "Clear all",
    "hist.empty": "No scans yet. Run a scan and it appears here.",
    "hist.selectHint": "Select a scan to view its offsets, or pin two and Compare.",
    "hist.noFindings": "No findings stored for this scan.",
    "hist.found": "found",
    "hist.unknownVer": "Unknown version",
    "hist.delete": "Delete",
    "hist.export": "Export",
    "hist.exported": "Exported",
    "hist.scanDetail": "Scan details",
  },
  ja: {
    "nav.history": "履歴",
    "hist.title": "履歴",
    "hist.sub": "すべてのスキャンをバージョン別に整理",
    "hist.refresh": "更新",
    "hist.compare": "A ↔ B を比較",
    "hist.clear": "すべて削除",
    "hist.empty": "まだスキャンがありません。スキャンするとここに表示されます。",
    "hist.selectHint": "スキャンを選択してオフセットを表示するか、2つを固定して比較してください。",
    "hist.noFindings": "このスキャンに保存された結果はありません。",
    "hist.found": "発見",
    "hist.unknownVer": "不明なバージョン",
    "hist.delete": "削除",
    "hist.export": "エクスポート",
    "hist.exported": "エクスポートしました",
    "hist.scanDetail": "スキャンの詳細",
  },
  zh: {
    "nav.history": "历史",
    "hist.title": "历史",
    "hist.sub": "按版本分组的所有扫描",
    "hist.refresh": "刷新",
    "hist.compare": "比较 A ↔ B",
    "hist.clear": "清除全部",
    "hist.empty": "暂无扫描。运行一次扫描后会显示在此处。",
    "hist.selectHint": "选择一次扫描查看其偏移，或固定两个进行比较。",
    "hist.noFindings": "此扫描没有存储的结果。",
    "hist.found": "找到",
    "hist.unknownVer": "未知版本",
    "hist.delete": "删除",
    "hist.export": "导出",
    "hist.exported": "已导出",
    "hist.scanDetail": "扫描详情",
  },
  ko: {
    "nav.history": "기록",
    "hist.title": "기록",
    "hist.sub": "버전별로 정리된 모든 스캔",
    "hist.refresh": "새로고침",
    "hist.compare": "A ↔ B 비교",
    "hist.clear": "모두 지우기",
    "hist.empty": "아직 스캔이 없습니다. 스캔을 실행하면 여기에 표시됩니다.",
    "hist.selectHint": "스캔을 선택하여 오프셋을 보거나 두 개를 고정해 비교하세요.",
    "hist.noFindings": "이 스캔에 저장된 결과가 없습니다.",
    "hist.found": "발견",
    "hist.unknownVer": "알 수 없는 버전",
    "hist.delete": "삭제",
    "hist.export": "내보내기",
    "hist.exported": "내보냈습니다",
    "hist.scanDetail": "스캔 세부정보",
  },
  he: {
    "nav.history": "היסטוריה",
    "hist.title": "היסטוריה",
    "hist.sub": "כל הסריקות, מקובצות לפי גרסה",
    "hist.refresh": "רענן",
    "hist.compare": "השווה A ↔ B",
    "hist.clear": "נקה הכול",
    "hist.empty": "אין עדיין סריקות. הרץ סריקה והיא תופיע כאן.",
    "hist.selectHint": "בחר סריקה כדי לראות את ההיסטים, או נעץ שתיים והשווה.",
    "hist.noFindings": "אין ממצאים שמורים לסריקה זו.",
    "hist.found": "נמצאו",
    "hist.unknownVer": "גרסה לא ידועה",
    "hist.delete": "מחק",
    "hist.export": "ייצוא",
    "hist.exported": "יוצא",
    "hist.scanDetail": "פרטי הסריקה",
  },
};
Object.keys(HIST_I18N).forEach((lang) => Object.assign(I18N[lang], HIST_I18N[lang]));

const PINS_I18N = {
  en: { "hist.compare": "Compare versions", "hist.base": "Base", "hist.target": "Target", "hist.pinHint": "Pick a base and a target version to compare.", "hist.unset": "not set", "hist.setBase": "Set as base", "hist.setTarget": "Set as target" },
  ja: { "hist.compare": "バージョンを比較", "hist.base": "基準", "hist.target": "対象", "hist.pinHint": "比較する基準バージョンと対象バージョンを選択してください。", "hist.unset": "未設定", "hist.setBase": "基準に設定", "hist.setTarget": "対象に設定" },
  zh: { "hist.compare": "比较版本", "hist.base": "基准", "hist.target": "目标", "hist.pinHint": "请选择要比较的基准版本和目标版本。", "hist.unset": "未设置", "hist.setBase": "设为基准", "hist.setTarget": "设为目标" },
  ko: { "hist.compare": "버전 비교", "hist.base": "기준", "hist.target": "대상", "hist.pinHint": "비교할 기준 버전과 대상 버전을 선택하세요.", "hist.unset": "미설정", "hist.setBase": "기준으로 설정", "hist.setTarget": "대상으로 설정" },
  he: { "hist.compare": "השווה גרסאות", "hist.base": "בסיס", "hist.target": "יעד", "hist.pinHint": "בחר גרסת בסיס וגרסת יעד להשוואה.", "hist.unset": "לא הוגדר", "hist.setBase": "הגדר כבסיס", "hist.setTarget": "הגדר כיעד" },
};
Object.keys(PINS_I18N).forEach((lang) => Object.assign(I18N[lang], PINS_I18N[lang]));

const SEARCH_I18N = { en: "Search offsets…", ja: "オフセットを検索…", zh: "搜索偏移…", ko: "오프셋 검색…", he: "חיפוש היסטים…" };
Object.keys(SEARCH_I18N).forEach((lang) => {
  I18N[lang]["hist.search"] = SEARCH_I18N[lang];
});

const RAND_I18N = {
  en: { "set.randomize": "Randomize instead of blur", "set.randomizeDesc": "Showcase mode: replace masked data with realistic fake values instead of blurring it." },
  ja: { "set.randomize": "ぼかしの代わりにランダム化", "set.randomizeDesc": "ショーケースモード：マスクしたデータをぼかす代わりに、本物らしい偽の値に置き換えます。" },
  zh: { "set.randomize": "随机化而非模糊", "set.randomizeDesc": "展示模式：用逼真的随机假数据替换被遮罩的数据，而不是模糊处理。" },
  ko: { "set.randomize": "흐리게 대신 무작위화", "set.randomizeDesc": "쇼케이스 모드: 마스킹된 데이터를 흐리게 처리하는 대신 사실적인 가짜 값으로 대체합니다." },
  he: { "set.randomize": "אקראי במקום טשטוש", "set.randomizeDesc": "מצב תצוגה: החלף נתונים ממוסכים בערכים מזויפים אך מציאותיים במקום לטשטש." },
};
Object.keys(RAND_I18N).forEach((lang) => Object.assign(I18N[lang], RAND_I18N[lang]));

const TAB_I18N = {
  en: { "hist.matrix": "Matrix", "hist.needTwo": "Need at least two versions to build a matrix.", "hist.matrixTitle": "Matrix ({n})", "hist.rename": "Double-click to rename", "hist.diffFiles": "Diff files", "hist.diffPickTwo": "Select two dump files to compare.", "diag.confidence": "Confidence", "diag.trace": "Resolver trace", "diag.candidates": "Candidates" },
  ja: { "hist.matrix": "マトリクス", "hist.needTwo": "マトリクスを作成するには2つ以上のバージョンが必要です。", "hist.matrixTitle": "マトリクス ({n})", "hist.rename": "ダブルクリックで名前を変更", "hist.diffFiles": "ファイルを比較", "hist.diffPickTwo": "比較する2つのダンプファイルを選択してください。", "diag.confidence": "信頼度", "diag.trace": "リゾルバートレース", "diag.candidates": "候補" },
  zh: { "hist.matrix": "矩阵", "hist.needTwo": "构建矩阵至少需要两个版本。", "hist.matrixTitle": "矩阵 ({n})", "hist.rename": "双击重命名", "hist.diffFiles": "比较文件", "hist.diffPickTwo": "请选择两个转储文件进行比较。", "diag.confidence": "置信度", "diag.trace": "解析器追踪", "diag.candidates": "候选" },
  ko: { "hist.matrix": "매트릭스", "hist.needTwo": "매트릭스를 만들려면 두 개 이상의 버전이 필요합니다.", "hist.matrixTitle": "매트릭스 ({n})", "hist.rename": "더블클릭하여 이름 변경", "hist.diffFiles": "파일 비교", "hist.diffPickTwo": "비교할 덤프 파일 두 개를 선택하세요.", "diag.confidence": "신뢰도", "diag.trace": "리졸버 추적", "diag.candidates": "후보" },
  he: { "hist.matrix": "מטריצה", "hist.needTwo": "נדרשות לפחות שתי גרסאות ליצירת מטריצה.", "hist.matrixTitle": "מטריצה ({n})", "hist.rename": "לחיצה כפולה לשינוי שם", "hist.diffFiles": "השווה קבצים", "hist.diffPickTwo": "בחר שני קבצי dump להשוואה.", "diag.confidence": "ביטחון", "diag.trace": "מעקב פותר", "diag.candidates": "מועמדים" },
};
Object.keys(TAB_I18N).forEach((lang) => Object.assign(I18N[lang], TAB_I18N[lang]));

const ASM_I18N = {
  en: { "hist.loading": "Disassembling…", "hist.noBytes": "No bytes captured for this symbol." },
  ja: { "hist.loading": "逆アセンブル中…", "hist.noBytes": "このシンボルのバイトは記録されていません。" },
  zh: { "hist.loading": "正在反汇编…", "hist.noBytes": "未记录此符号的字节。" },
  ko: { "hist.loading": "디스어셈블 중…", "hist.noBytes": "이 심볼에 대해 기록된 바이트가 없습니다." },
  he: { "hist.loading": "מפרק לאסמבלי…", "hist.noBytes": "לא נשמרו בייטים עבור סמל זה." },
};
Object.keys(ASM_I18N).forEach((lang) => Object.assign(I18N[lang], ASM_I18N[lang]));

const ASMSCAN_I18N = {
  en: {
    "nav.asmscan": "Assembly scan", "asm.title": "Assembly scan", "asm.sub": "Find code by instruction, with wildcards",
    "asm.ph": "push\ncall\ntest eax,eax", "asm.scan": "Scan", "asm.from": "From", "asm.to": "To",
    "asm.help": "Wildcards: * any chars · ? one char · ^ line start · $ line end. Each line is one instruction; matches run consecutively.",
    "asm.filter": "Filter results…", "asm.empty": "Enter assembly lines and press Scan.", "asm.none": "No matches.",
    "asm.needLines": "Enter at least one assembly line.", "asm.match": "{n} matches", "asm.matchOne": "1 match",
    "asm.truncated": "showing first {shown} of {total}", "asm.noTarget": "Set a target in the Workspace first.",
    "asm.targetSummary": "{target} · {module} · {arch}", "asm.save": "Save as pattern", "asm.running": "Scanning…",
  },
  ja: {
    "nav.asmscan": "アセンブリスキャン", "asm.title": "アセンブリスキャン", "asm.sub": "命令でコードを検索（ワイルドカード対応）",
    "asm.ph": "push\ncall\ntest eax,eax", "asm.scan": "スキャン", "asm.from": "開始", "asm.to": "終了",
    "asm.help": "ワイルドカード: * 任意の文字 · ? 1文字 · ^ 行頭 · $ 行末。各行が1命令で、連続して一致します。",
    "asm.filter": "結果をフィルター…", "asm.empty": "アセンブリ行を入力して「スキャン」を押してください。", "asm.none": "一致なし。",
    "asm.needLines": "アセンブリ行を1つ以上入力してください。", "asm.match": "{n} 件の一致", "asm.matchOne": "1 件の一致",
    "asm.truncated": "{total} 件中 {shown} 件を表示", "asm.noTarget": "先にワークスペースで対象を設定してください。",
    "asm.targetSummary": "{target} · {module} · {arch}", "asm.save": "パターンとして保存", "asm.running": "スキャン中…",
  },
  zh: {
    "nav.asmscan": "汇编扫描", "asm.title": "汇编扫描", "asm.sub": "按指令查找代码（支持通配符）",
    "asm.ph": "push\ncall\ntest eax,eax", "asm.scan": "扫描", "asm.from": "起始", "asm.to": "结束",
    "asm.help": "通配符：* 任意字符 · ? 单个字符 · ^ 行首 · $ 行尾。每行一条指令，连续匹配。",
    "asm.filter": "筛选结果…", "asm.empty": "输入汇编行并点击扫描。", "asm.none": "无匹配。",
    "asm.needLines": "请至少输入一行汇编。", "asm.match": "{n} 个匹配", "asm.matchOne": "1 个匹配",
    "asm.truncated": "显示 {total} 中的前 {shown} 个", "asm.noTarget": "请先在工作区设置目标。",
    "asm.targetSummary": "{target} · {module} · {arch}", "asm.save": "另存为模式", "asm.running": "扫描中…",
  },
  ko: {
    "nav.asmscan": "어셈블리 스캔", "asm.title": "어셈블리 스캔", "asm.sub": "명령어로 코드 찾기 (와일드카드 지원)",
    "asm.ph": "push\ncall\ntest eax,eax", "asm.scan": "스캔", "asm.from": "시작", "asm.to": "끝",
    "asm.help": "와일드카드: * 임의 문자 · ? 한 문자 · ^ 줄 시작 · $ 줄 끝. 각 줄은 한 명령어이며 연속으로 일치합니다.",
    "asm.filter": "결과 필터…", "asm.empty": "어셈블리 줄을 입력하고 스캔을 누르세요.", "asm.none": "일치 항목 없음.",
    "asm.needLines": "어셈블리 줄을 하나 이상 입력하세요.", "asm.match": "{n}개 일치", "asm.matchOne": "1개 일치",
    "asm.truncated": "{total}개 중 처음 {shown}개 표시", "asm.noTarget": "먼저 작업 공간에서 대상을 설정하세요.",
    "asm.targetSummary": "{target} · {module} · {arch}", "asm.save": "패턴으로 저장", "asm.running": "스캔 중…",
  },
  he: {
    "nav.asmscan": "סריקה לפי פקודות", "asm.title": "סריקה לפי פקודות", "asm.sub": "מצא קוד לפי פקודה, עם תווים כלליים",
    "asm.ph": "push\ncall\ntest eax,eax", "asm.scan": "סרוק", "asm.from": "מתחילת", "asm.to": "עד",
    "asm.help": "תווים כלליים: * כל תו · ? תו אחד · ^ תחילת שורה · $ סוף שורה. כל שורה היא פקודה אחת, וההתאמות רצופות.",
    "asm.filter": "סנן תוצאות…", "asm.empty": "הזן שורות אסמבלי ולחץ על סרוק.", "asm.none": "אין התאמות.",
    "asm.needLines": "הזן לפחות שורת אסמבלי אחת.", "asm.match": "{n} התאמות", "asm.matchOne": "התאמה אחת",
    "asm.truncated": "מציג {shown} מתוך {total} הראשונות", "asm.noTarget": "הגדר תחילה יעד בסביבת העבודה.",
    "asm.targetSummary": "{target} · {module} · {arch}", "asm.save": "שמור כתבנית", "asm.running": "סורק…",
  },
};
Object.keys(ASMSCAN_I18N).forEach((lang) => Object.assign(I18N[lang], ASMSCAN_I18N[lang]));

const SIG_I18N = {
  en: {
    "nav.sigmaker": "Signature maker", "sig.title": "Signature maker", "sig.sub": "Generate a cross-version signature from client files",
    "sig.pick": "Pick files", "sig.generate": "Generate", "sig.json": "JSON", "sig.modeAob": "From signature", "sig.modeRef": "From address",
    "sig.aobPh": "48 8B ?? ?? ?? ??  (an existing AOB to harden)", "sig.rvaPh": "0x… (RVA in the reference)",
    "sig.empty": "Add client files and choose a target, then Generate.", "sig.generating": "Generating…", "sig.noFiles": "Pick at least one client file.",
    "sig.needAob": "Enter a signature to harden.", "sig.needRva": "Choose a reference client and enter an RVA.", "sig.none": "No safe signature found.",
    "sig.unpacked": "Unpacked", "sig.packed": "Packed", "sig.packedAlert": "One or more selected binaries look packed. Signatures built from them may be unreliable, so use an unpacked or dumped image.",
    "sig.chosen": "Chosen", "sig.alternates": "Alternates", "sig.rejected": "Rejected", "sig.copy": "Copy", "sig.save": "Save as pattern",
    "sig.builds": "{n} unique build(s)", "sig.grade": "Grade", "sig.bytesFixed": "{bytes} bytes · {fixed} fixed · {wild} wild · {ratio}",
    "sig.colVersion": "Version", "sig.colMatch": "Match RVA", "sig.colTarget": "Resolved target",
    "sig.refColumn": "reference", "sig.diagnostics": "Diagnostics", "sig.saved": "Added to pattern list",
    "sig.summary": "{arch} · {files} file(s) · {builds} unique build(s)", "sig.dupBuilds": "Duplicate builds",
    "sig.gradeLegend": "Grade legend",
    "sig.holdout": "Holdout validation", "sig.holdoutOk": "matched the held-out build",
    "sig.holdoutMiss": "did not match the held-out build", "sig.holdoutNone": "no signature without this build",
    "sig.stringAnchor": "String anchor (survives patches)", "sig.stringAnchorHint": "Paste this into your pattern file as a name = ... line; it locates the function by a referenced string, surviving version changes that move the bytes.",
    "sig.copy": "Copy", "sig.copied": "Copied",
    "sig.negHits": "Negative corpus matches", "sig.negHitCount": "{n} match(es)",
    "sig.negatives": "Negative modules", "sig.addNegatives": "Add negatives", "sig.negativesHint": "Unrelated modules the signature must NOT match",
    "sig.gradeA": "Content-validated anchor, relocation-safe.", "sig.gradeB": "Relocation-safe, not content-validated.",
    "sig.gradeC": "Weak: absolute or unresolved reference, or cross-build mismatch.", "sig.gradeD": "An input looks packed or protected; provisional.",
    "sig.gradeF": "Rejected: too few fixed bytes, low ratio, or unsupported relocation.",
    "sig.modeBoth": "Both", "sig.separate": "Separate", "sig.cross": "Cross-validate",
    "sig.separateHint": "Signature and address are independent targets.",
    "sig.crossHint": "Each signature must resolve to the address on the same line.",
    "sig.aobLabel": "Signatures (one per line)", "sig.refLabel": "Reference client", "sig.rvaLabel": "Addresses, RVA (one per line)",
    "sig.loadFile": "Load file", "sig.loadedLines": "Loaded {n} line(s)", "sig.dismiss": "Dismiss", "sig.jobProgress": "[{job}/{jobs}]",
    "sig.crossOk": "Resolves to {rva} as expected.", "sig.crossMismatch": "Resolves to {got}, expected {expected}.",
    "sig.crossNoMatch": "no match", "sig.crossUneven": "{sigs} signature(s) and {rvas} address(es); extra lines are ignored.",
  },
  ja: {
    "nav.sigmaker": "シグネチャメーカー", "sig.title": "シグネチャメーカー", "sig.sub": "クライアントファイルからバージョン横断シグネチャを生成",
    "sig.pick": "ファイルを選択", "sig.generate": "生成", "sig.json": "JSON", "sig.modeAob": "シグネチャから", "sig.modeRef": "アドレスから",
    "sig.aobPh": "48 8B ?? ?? ?? ??（強化する既存のAOB）", "sig.rvaPh": "0x…（参照内のRVA）",
    "sig.empty": "クライアントファイルと対象を選び、「生成」を押してください。", "sig.generating": "生成中…", "sig.noFiles": "クライアントファイルを1つ以上選択してください。",
    "sig.needAob": "強化するシグネチャを入力してください。", "sig.needRva": "参照クライアントを選びRVAを入力してください。", "sig.none": "安全なシグネチャが見つかりません。",
    "sig.unpacked": "非パック", "sig.packed": "パック", "sig.packedAlert": "選択したバイナリの一部はパックされている可能性があります。生成されたシグネチャは信頼できない場合があります。展開済みのイメージを使用してください。",
    "sig.chosen": "採用", "sig.alternates": "代替", "sig.rejected": "却下", "sig.copy": "コピー", "sig.save": "パターンとして保存",
    "sig.builds": "{n} 個の一意ビルド", "sig.grade": "評価", "sig.bytesFixed": "{bytes} バイト · 固定 {fixed} · ワイルド {wild} · {ratio}",
    "sig.colVersion": "バージョン", "sig.colMatch": "一致 RVA", "sig.colTarget": "解決先",
    "sig.refColumn": "参照", "sig.diagnostics": "診断", "sig.saved": "パターン一覧に追加しました",
    "sig.summary": "{arch} · {files} ファイル · {builds} 個の一意ビルド", "sig.dupBuilds": "重複ビルド",
    "sig.gradeLegend": "評価の凡例",
    "sig.gradeA": "内容検証済みのアンカー。再配置に安全。", "sig.gradeB": "再配置に安全だが内容は未検証。",
    "sig.gradeC": "弱い。絶対参照または未解決の参照、もしくはビルド間の不一致。", "sig.gradeD": "入力がパックまたは保護されている可能性。暫定。",
    "sig.gradeF": "却下。固定バイト不足、低い比率、または未対応の再配置。",
    "sig.modeBoth": "両方", "sig.separate": "個別", "sig.cross": "相互検証",
    "sig.separateHint": "シグネチャとアドレスは独立した対象です。",
    "sig.crossHint": "各シグネチャは同じ行のアドレスに解決する必要があります。",
    "sig.aobLabel": "シグネチャ（1行に1つ）", "sig.refLabel": "参照クライアント", "sig.rvaLabel": "アドレス、RVA（1行に1つ）",
    "sig.loadFile": "ファイルを読み込み", "sig.loadedLines": "{n} 行を読み込みました", "sig.dismiss": "閉じる", "sig.jobProgress": "[{job}/{jobs}]",
    "sig.crossOk": "期待どおり {rva} に解決しました。", "sig.crossMismatch": "{got} に解決しました。期待値は {expected} です。",
    "sig.crossNoMatch": "一致なし", "sig.crossUneven": "シグネチャ {sigs} 個、アドレス {rvas} 個。余分な行は無視されます。",
  },
  zh: {
    "nav.sigmaker": "特征码生成器", "sig.title": "特征码生成器", "sig.sub": "从客户端文件生成跨版本特征码",
    "sig.pick": "选择文件", "sig.generate": "生成", "sig.json": "JSON", "sig.modeAob": "从特征码", "sig.modeRef": "从地址",
    "sig.aobPh": "48 8B ?? ?? ?? ??（要强化的现有 AOB）", "sig.rvaPh": "0x…（参考中的 RVA）",
    "sig.empty": "选择客户端文件和目标，然后点击生成。", "sig.generating": "生成中…", "sig.noFiles": "请至少选择一个客户端文件。",
    "sig.needAob": "请输入要强化的特征码。", "sig.needRva": "请选择参考客户端并输入 RVA。", "sig.none": "未找到安全的特征码。",
    "sig.unpacked": "未加壳", "sig.packed": "已加壳", "sig.packedAlert": "选中的某些二进制文件可能已加壳，由它们生成的特征码可能不可靠；请使用未加壳或已转储的映像。",
    "sig.chosen": "已选", "sig.alternates": "备选", "sig.rejected": "已拒绝", "sig.copy": "复制", "sig.save": "另存为模式",
    "sig.builds": "{n} 个唯一版本", "sig.grade": "等级", "sig.bytesFixed": "{bytes} 字节 · {fixed} 固定 · {wild} 通配 · {ratio}",
    "sig.colVersion": "版本", "sig.colMatch": "匹配 RVA", "sig.colTarget": "解析目标",
    "sig.refColumn": "参考", "sig.diagnostics": "诊断", "sig.saved": "已添加到模式列表",
    "sig.summary": "{arch} · {files} 个文件 · {builds} 个唯一版本", "sig.dupBuilds": "重复版本",
    "sig.gradeLegend": "等级图例",
    "sig.gradeA": "经内容验证的锚点，重定位安全。", "sig.gradeB": "重定位安全，但未经内容验证。",
    "sig.gradeC": "较弱：绝对或未解析的引用，或跨版本不一致。", "sig.gradeD": "某个输入可能已加壳或受保护；暂定。",
    "sig.gradeF": "已拒绝：固定字节过少、比率过低或不支持的重定位。",
    "sig.modeBoth": "两者", "sig.separate": "分别", "sig.cross": "交叉验证",
    "sig.separateHint": "特征码和地址是独立的目标。",
    "sig.crossHint": "每个特征码必须解析到同一行的地址。",
    "sig.aobLabel": "特征码（每行一个）", "sig.refLabel": "参考客户端", "sig.rvaLabel": "地址，RVA（每行一个）",
    "sig.loadFile": "加载文件", "sig.loadedLines": "已加载 {n} 行", "sig.dismiss": "关闭", "sig.jobProgress": "[{job}/{jobs}]",
    "sig.crossOk": "按预期解析到 {rva}。", "sig.crossMismatch": "解析到 {got}，预期为 {expected}。",
    "sig.crossNoMatch": "无匹配", "sig.crossUneven": "{sigs} 个特征码，{rvas} 个地址；多余的行将被忽略。",
  },
  ko: {
    "nav.sigmaker": "시그니처 메이커", "sig.title": "시그니처 메이커", "sig.sub": "클라이언트 파일로 버전 간 시그니처 생성",
    "sig.pick": "파일 선택", "sig.generate": "생성", "sig.json": "JSON", "sig.modeAob": "시그니처에서", "sig.modeRef": "주소에서",
    "sig.aobPh": "48 8B ?? ?? ?? ?? (강화할 기존 AOB)", "sig.rvaPh": "0x… (참조의 RVA)",
    "sig.empty": "클라이언트 파일과 대상을 선택한 후 생성하세요.", "sig.generating": "생성 중…", "sig.noFiles": "클라이언트 파일을 하나 이상 선택하세요.",
    "sig.needAob": "강화할 시그니처를 입력하세요.", "sig.needRva": "참조 클라이언트를 선택하고 RVA를 입력하세요.", "sig.none": "안전한 시그니처를 찾지 못했습니다.",
    "sig.unpacked": "비패킹", "sig.packed": "패킹됨", "sig.packedAlert": "선택한 바이너리 중 일부가 패킹된 것으로 보입니다. 생성된 시그니처가 신뢰할 수 없을 수 있습니다. 언패킹되거나 덤프된 이미지를 사용하세요.",
    "sig.chosen": "선택됨", "sig.alternates": "대안", "sig.rejected": "거부됨", "sig.copy": "복사", "sig.save": "패턴으로 저장",
    "sig.builds": "고유 빌드 {n}개", "sig.grade": "등급", "sig.bytesFixed": "{bytes} 바이트 · 고정 {fixed} · 와일드 {wild} · {ratio}",
    "sig.colVersion": "버전", "sig.colMatch": "일치 RVA", "sig.colTarget": "해결된 대상",
    "sig.refColumn": "참조", "sig.diagnostics": "진단", "sig.saved": "패턴 목록에 추가했습니다",
    "sig.summary": "{arch} · 파일 {files}개 · 고유 빌드 {builds}개", "sig.dupBuilds": "중복 빌드",
    "sig.gradeLegend": "등급 범례",
    "sig.gradeA": "내용 검증된 앵커, 재배치 안전.", "sig.gradeB": "재배치 안전하지만 내용 미검증.",
    "sig.gradeC": "약함: 절대 또는 미해결 참조, 또는 빌드 간 불일치.", "sig.gradeD": "입력이 패킹되거나 보호된 것으로 보임. 잠정적.",
    "sig.gradeF": "거부됨: 고정 바이트 부족, 낮은 비율 또는 미지원 재배치.",
    "sig.modeBoth": "둘 다", "sig.separate": "개별", "sig.cross": "교차 검증",
    "sig.separateHint": "시그니처와 주소는 독립적인 대상입니다.",
    "sig.crossHint": "각 시그니처는 같은 줄의 주소로 해결되어야 합니다.",
    "sig.aobLabel": "시그니처 (한 줄에 하나)", "sig.refLabel": "참조 클라이언트", "sig.rvaLabel": "주소, RVA (한 줄에 하나)",
    "sig.loadFile": "파일 불러오기", "sig.loadedLines": "{n}개 줄을 불러왔습니다", "sig.dismiss": "닫기", "sig.jobProgress": "[{job}/{jobs}]",
    "sig.crossOk": "예상대로 {rva}로 해결되었습니다.", "sig.crossMismatch": "{got}로 해결되었습니다. 예상값은 {expected}입니다.",
    "sig.crossNoMatch": "일치 없음", "sig.crossUneven": "시그니처 {sigs}개, 주소 {rvas}개. 남는 줄은 무시됩니다.",
  },
  he: {
    "nav.sigmaker": "יוצר חתימות", "sig.title": "יוצר חתימות", "sig.sub": "יצירת חתימה חוצת גרסאות מקבצי לקוח",
    "sig.pick": "בחר קבצים", "sig.generate": "צור", "sig.json": "JSON", "sig.modeAob": "מתוך חתימה", "sig.modeRef": "מתוך כתובת",
    "sig.aobPh": "48 8B ?? ?? ?? ??  (AOB קיים לחיזוק)", "sig.rvaPh": "0x… (RVA בקובץ הייחוס)",
    "sig.empty": "בחר קבצי לקוח ויעד, ולאחר מכן לחץ על צור.", "sig.generating": "יוצר…", "sig.noFiles": "בחר לפחות קובץ לקוח אחד.",
    "sig.needAob": "הזן חתימה לחיזוק.", "sig.needRva": "בחר קובץ ייחוס והזן RVA.", "sig.none": "לא נמצאה חתימה בטוחה.",
    "sig.unpacked": "לא ארוז", "sig.packed": "ארוז", "sig.packedAlert": "חלק מהקבצים שנבחרו נראים ארוזים. חתימות שנוצרות מהם עלולות להיות לא אמינות; השתמש בתמונה לא ארוזה.",
    "sig.chosen": "נבחר", "sig.alternates": "חלופות", "sig.rejected": "נדחו", "sig.copy": "העתק", "sig.save": "שמור כתבנית",
    "sig.builds": "{n} בנייות ייחודיות", "sig.grade": "ציון", "sig.bytesFixed": "{bytes} בייטים · {fixed} קבועים · {wild} כלליים · {ratio}",
    "sig.colVersion": "גרסה", "sig.colMatch": "RVA תואם", "sig.colTarget": "יעד שנפתר",
    "sig.refColumn": "ייחוס", "sig.diagnostics": "אבחון", "sig.saved": "נוסף לרשימת התבניות",
    "sig.summary": "{arch} · {files} קבצים · {builds} בנייות ייחודיות", "sig.dupBuilds": "בנייות כפולות",
    "sig.gradeLegend": "מקרא ציונים",
    "sig.gradeA": "עוגן מאומת תוכן, בטוח למיקום מחדש.", "sig.gradeB": "בטוח למיקום מחדש, אך התוכן לא אומת.",
    "sig.gradeC": "חלש: הפניה מוחלטת או לא פתורה, או חוסר עקביות בין בנייות.", "sig.gradeD": "אחד הקבצים נראה ארוז או מוגן; זמני.",
    "sig.gradeF": "נדחה: מעט בייטים קבועים, יחס נמוך, או מיקום מחדש שאינו נתמך.",
    "sig.modeBoth": "שניהם", "sig.separate": "בנפרד", "sig.cross": "אימות צולב",
    "sig.separateHint": "החתימה והכתובת הן יעדים נפרדים.",
    "sig.crossHint": "כל חתימה חייבת להתפענח לכתובת באותה שורה.",
    "sig.aobLabel": "חתימות (אחת בכל שורה)", "sig.refLabel": "קובץ ייחוס", "sig.rvaLabel": "כתובות, RVA (אחת בכל שורה)",
    "sig.loadFile": "טען קובץ", "sig.loadedLines": "נטענו {n} שורות", "sig.dismiss": "סגור", "sig.jobProgress": "[{job}/{jobs}]",
    "sig.crossOk": "מתפענח אל {rva} כצפוי.", "sig.crossMismatch": "מתפענח אל {got}, צפוי {expected}.",
    "sig.crossNoMatch": "אין התאמה", "sig.crossUneven": "{sigs} חתימות ו-{rvas} כתובות; שורות עודפות יתעלמו.",
  },
};
Object.keys(SIG_I18N).forEach((lang) => Object.assign(I18N[lang], SIG_I18N[lang]));

const ABOUT_I18N = {
  en: {
    "nav.about": "About", "about.title": "About", "about.sub": "Version, license, and project information",
    "about.tagline": "Cross-version signature and offset toolkit for MapleStory clients.",
    "about.desc": "MapleDumper finds, generates, and validates byte signatures and offsets that survive client patches. Feed it several client builds and it produces the highest-confidence pattern that resolves the same target in every version.",
    "about.f1": "Cross-version Signature Maker with confidence grading.",
    "about.f2": "Assembly scan, pattern editor, and version history comparison.",
    "about.f3": "Privacy mask for safe screenshots and sharing.",
    "about.licenseLabel": "License", "about.repoLabel": "Repository", "about.copyHint": "Click to copy",
  },
  ja: {
    "nav.about": "情報", "about.title": "情報", "about.sub": "バージョン、ライセンス、プロジェクト情報",
    "about.tagline": "MapleStory クライアント向けのバージョン横断シグネチャ/オフセットツールキット。",
    "about.desc": "MapleDumper はクライアントのパッチを越えて有効なバイトシグネチャとオフセットを検出、生成、検証します。複数のクライアントビルドを与えると、すべてのバージョンで同じ対象を解決する最も信頼性の高いパターンを生成します。",
    "about.f1": "信頼度評価付きのバージョン横断シグネチャメーカー。",
    "about.f2": "アセンブリスキャン、パターンエディタ、バージョン履歴の比較。",
    "about.f3": "安全なスクリーンショットと共有のためのプライバシーマスク。",
    "about.licenseLabel": "ライセンス", "about.repoLabel": "リポジトリ", "about.copyHint": "クリックでコピー",
  },
  zh: {
    "nav.about": "关于", "about.title": "关于", "about.sub": "版本、许可证和项目信息",
    "about.tagline": "适用于 MapleStory 客户端的跨版本特征码与偏移工具包。",
    "about.desc": "MapleDumper 可检测、生成并验证能在客户端更新后依然有效的字节特征码和偏移。提供多个客户端版本，它会生成在每个版本中都解析到相同目标的最高置信度模式。",
    "about.f1": "带置信度评级的跨版本特征码生成器。",
    "about.f2": "汇编扫描、模式编辑器和版本历史比较。",
    "about.f3": "用于安全截图和分享的隐私遮罩。",
    "about.licenseLabel": "许可证", "about.repoLabel": "仓库", "about.copyHint": "点击复制",
  },
  ko: {
    "nav.about": "정보", "about.title": "정보", "about.sub": "버전, 라이선스 및 프로젝트 정보",
    "about.tagline": "MapleStory 클라이언트를 위한 버전 간 시그니처 및 오프셋 도구 모음.",
    "about.desc": "MapleDumper는 클라이언트 패치 후에도 유효한 바이트 시그니처와 오프셋을 찾고 생성하고 검증합니다. 여러 클라이언트 빌드를 제공하면 모든 버전에서 동일한 대상을 해결하는 가장 신뢰도 높은 패턴을 만듭니다.",
    "about.f1": "신뢰도 등급이 포함된 버전 간 시그니처 메이커.",
    "about.f2": "어셈블리 스캔, 패턴 편집기 및 버전 기록 비교.",
    "about.f3": "안전한 스크린샷과 공유를 위한 개인정보 마스크.",
    "about.licenseLabel": "라이선스", "about.repoLabel": "저장소", "about.copyHint": "클릭하여 복사",
  },
  he: {
    "nav.about": "אודות", "about.title": "אודות", "about.sub": "מידע על גרסה, רישיון ופרויקט",
    "about.tagline": "ערכת כלים לחתימות והיסטים חוצי גרסאות עבור לקוחות MapleStory.",
    "about.desc": "MapleDumper מאתר, יוצר ומאמת חתימות בייטים והיסטים ששורדים עדכוני לקוח. הזן כמה גרסאות לקוח והוא יפיק את התבנית בעלת הביטחון הגבוה ביותר שמזהה את אותו יעד בכל גרסה.",
    "about.f1": "יוצר חתימות חוצה גרסאות עם דירוג ביטחון.",
    "about.f2": "סריקת אסמבלי, עורך תבניות והשוואת היסטוריית גרסאות.",
    "about.f3": "מסכת פרטיות לצילומי מסך ושיתוף בטוחים.",
    "about.licenseLabel": "רישיון", "about.repoLabel": "מאגר", "about.copyHint": "לחץ להעתקה",
  },
};
Object.keys(ABOUT_I18N).forEach((lang) => Object.assign(I18N[lang], ABOUT_I18N[lang]));

const SIG_STAGE_I18N = {
  en: {
    "sig.stLoad": "Loading {label}…", "sig.stPack": "Checking for packers…",
    "sig.stDedup": "Grouping builds…", "sig.stRead": "Reading code ({index}/{total})…",
    "sig.stLocate": "Locating the target…", "sig.stDirect": "Scanning the direct match…",
    "sig.stBranch": "Scanning call and jmp sites…", "sig.stPtr": "Scanning pointer references…",
    "sig.stScore": "Scoring candidates…",
  },
  ja: {
    "sig.stLoad": "{label} を読み込み中…", "sig.stPack": "パッカーを確認中…",
    "sig.stDedup": "ビルドをグループ化中…", "sig.stRead": "コードを読み込み中（{index}/{total}）…",
    "sig.stLocate": "対象を特定中…", "sig.stDirect": "直接一致をスキャン中…",
    "sig.stBranch": "call/jmp サイトをスキャン中…", "sig.stPtr": "ポインター参照をスキャン中…",
    "sig.stScore": "候補を評価中…",
  },
  zh: {
    "sig.stLoad": "正在加载 {label}…", "sig.stPack": "正在检查加壳…",
    "sig.stDedup": "正在分组版本…", "sig.stRead": "正在读取代码（{index}/{total}）…",
    "sig.stLocate": "正在定位目标…", "sig.stDirect": "正在扫描直接匹配…",
    "sig.stBranch": "正在扫描 call/jmp 位置…", "sig.stPtr": "正在扫描指针引用…",
    "sig.stScore": "正在评估候选…",
  },
  ko: {
    "sig.stLoad": "{label} 불러오는 중…", "sig.stPack": "패킹 여부 확인 중…",
    "sig.stDedup": "빌드 그룹화 중…", "sig.stRead": "코드 읽는 중 ({index}/{total})…",
    "sig.stLocate": "대상 찾는 중…", "sig.stDirect": "직접 일치 스캔 중…",
    "sig.stBranch": "call/jmp 위치 스캔 중…", "sig.stPtr": "포인터 참조 스캔 중…",
    "sig.stScore": "후보 평가 중…",
  },
  he: {
    "sig.stLoad": "טוען את {label}…", "sig.stPack": "בודק אריזה…",
    "sig.stDedup": "מקבץ בנייות…", "sig.stRead": "קורא קוד ({index}/{total})…",
    "sig.stLocate": "מאתר את היעד…", "sig.stDirect": "סורק התאמה ישירה…",
    "sig.stBranch": "סורק אתרי call/jmp…", "sig.stPtr": "סורק הפניות מצביע…",
    "sig.stScore": "מדרג מועמדים…",
  },
};
Object.keys(SIG_STAGE_I18N).forEach((lang) => Object.assign(I18N[lang], SIG_STAGE_I18N[lang]));

const CTX_I18N = {
  en: {
    "ctx.copyName": "Copy name", "ctx.copyType": "Copy type", "ctx.copyCategory": "Copy category",
    "ctx.copySignature": "Copy signature", "ctx.copyNote": "Copy note",
    "ctx.copyJson": "Copy as JSON", "ctx.copyText": "Copy as text",
    "ctx.copyAllJson": "Copy all as JSON", "ctx.copyAllText": "Copy all as text",
  },
  ja: {
    "ctx.copyName": "名前をコピー", "ctx.copyType": "種類をコピー", "ctx.copyCategory": "カテゴリをコピー",
    "ctx.copySignature": "シグネチャをコピー", "ctx.copyNote": "メモをコピー",
    "ctx.copyJson": "JSON としてコピー", "ctx.copyText": "テキストとしてコピー",
    "ctx.copyAllJson": "すべてを JSON でコピー", "ctx.copyAllText": "すべてをテキストでコピー",
  },
  zh: {
    "ctx.copyName": "复制名称", "ctx.copyType": "复制类型", "ctx.copyCategory": "复制类别",
    "ctx.copySignature": "复制特征码", "ctx.copyNote": "复制备注",
    "ctx.copyJson": "复制为 JSON", "ctx.copyText": "复制为文本",
    "ctx.copyAllJson": "全部复制为 JSON", "ctx.copyAllText": "全部复制为文本",
  },
  ko: {
    "ctx.copyName": "이름 복사", "ctx.copyType": "유형 복사", "ctx.copyCategory": "카테고리 복사",
    "ctx.copySignature": "시그니처 복사", "ctx.copyNote": "메모 복사",
    "ctx.copyJson": "JSON으로 복사", "ctx.copyText": "텍스트로 복사",
    "ctx.copyAllJson": "전체를 JSON으로 복사", "ctx.copyAllText": "전체를 텍스트로 복사",
  },
  he: {
    "ctx.copyName": "העתק שם", "ctx.copyType": "העתק סוג", "ctx.copyCategory": "העתק קטגוריה",
    "ctx.copySignature": "העתק חתימה", "ctx.copyNote": "העתק הערה",
    "ctx.copyJson": "העתק כ-JSON", "ctx.copyText": "העתק כטקסט",
    "ctx.copyAllJson": "העתק הכול כ-JSON", "ctx.copyAllText": "העתק הכול כטקסט",
  },
};
Object.keys(CTX_I18N).forEach((lang) => Object.assign(I18N[lang], CTX_I18N[lang]));

const SIG_STAGE_KEY = {
  load: "sig.stLoad", pack: "sig.stPack", dedup: "sig.stDedup", read: "sig.stRead",
  locate: "sig.stLocate", direct: "sig.stDirect", branch: "sig.stBranch", ptr: "sig.stPtr",
  score: "sig.stScore",
};

function t(key, params) {
  const table = I18N[LANG] || I18N.en;
  let s = table[key] != null ? table[key] : I18N.en[key] != null ? I18N.en[key] : key;
  if (params) s = s.replace(/\{(\w+)\}/g, (m, k) => (params[k] != null ? params[k] : m));
  return s;
}
function applyStatic() {
  document.querySelectorAll("[data-i18n]").forEach((el) => (el.textContent = t(el.getAttribute("data-i18n"))));
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => el.setAttribute("placeholder", t(el.getAttribute("data-i18n-ph"))));
  document.querySelectorAll("[data-i18n-title]").forEach((el) => el.setAttribute("title", t(el.getAttribute("data-i18n-title"))));
}
function setLang(lang) {
  if (!I18N[lang]) lang = "en";
  LANG = lang;
  try {
    localStorage.setItem("lang", lang);
  } catch {
  }
  document.documentElement.setAttribute("lang", lang);
  document.documentElement.setAttribute("dir", RTL.has(lang) ? "rtl" : "ltr");
  applyStatic();
  if (onLangChange) onLangChange();
}
setLang(LANG);

const SVG = (inner) =>
  `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;

const ICONS = {
  grid: SVG('<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 12h18M12 3v18"/>'),
  "file-code": SVG('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="m10 13-2 2 2 2"/><path d="m14 17 2-2-2-2"/>'),
  terminal: SVG('<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>'),
  database: SVG('<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>'),
  shield: SVG('<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>'),
  activity: SVG('<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>'),
  boxes: SVG('<path d="M21 8 12 3 3 8l9 5 9-5z"/><path d="M3 8v8l9 5 9-5V8"/><path d="M12 13v8"/>'),
  play: SVG('<polygon points="6 3 20 12 6 21 6 3"/>'),
  square: SVG('<rect x="5" y="5" width="14" height="14" rx="2"/>'),
  cpu: SVG('<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/>'),
  download: SVG('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>'),
  chevron: SVG('<polyline points="6 9 12 15 18 9"/>'),
  folder: SVG('<path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2z"/>'),
  search: SVG('<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>'),
  copy: SVG('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>'),
  layers: SVG('<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>'),
  eye: SVG('<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>'),
  "eye-off": SVG('<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.4 10.4 0 0 1 12 5c6.5 0 10 7 10 7a13.5 13.5 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.5 13.5 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.39-1.61"/><path d="m2 2 20 20"/>'),
  settings: SVG('<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>'),
  globe: SVG('<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>'),
  diff: SVG('<line x1="12" y1="4" x2="12" y2="20"/><polyline points="7 9 4 12 7 15"/><polyline points="17 9 20 12 17 15"/>'),
  history: SVG('<path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l4 2"/>'),
  info: SVG('<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>'),
};

function injectIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach((el) => {
    const target = el.querySelector(".ico") || el;
    if (ICONS[el.dataset.icon]) target.innerHTML = ICONS[el.dataset.icon];
  });
}

const SEED = `# MapleDumper pattern list
# name = AOB   ; trailing note is optional
# suffixes pick a resolver: _PTR rip-relative, _OFF displacement, _HDR immediate, _CALL two-hop

[functions]
SendPacket_PTR = 48 8B ?? ?? ?? ?? ?? E8   ; outgoing packet sender
Recv_CALL = E8 ?? ?? ?? ?? 84 C0           ; inbound dispatch

[globals]
GameState = A1 ?? ?? ?? ?? 8B

[offsets]
Player_Hp_OFF = 8B 8E ?? ?? ?? ??          ; hp field on the character struct

[packets]
Login_HDR = C7 45 ?? ?? ?? ?? ??           ; login opcode immediate
`;

function loadMaskSettings() {
  const def = { sig: true, name: false, addr: false, cat: false, note: false, editor: true, output: true };
  try {
    return Object.assign(def, JSON.parse(localStorage.getItem("maskSettings") || "{}"));
  } catch {
    return def;
  }
}
function saveMaskSettings() {
  try {
    localStorage.setItem("maskSettings", JSON.stringify(state.mask));
  } catch {
  }
}
function loadMaskMode() {
  try {
    return localStorage.getItem("maskMode") || "blur";
  } catch {
    return "blur";
  }
}
function saveMaskMode() {
  try {
    localStorage.setItem("maskMode", state.maskMode);
  } catch {
  }
}

const state = {
  patternText: SEED,
  mask: loadMaskSettings(),
  maskMode: loadMaskMode(),
  patterns: [],
  editingIndex: -1,
  arch: "x64",
  wait: true,
  byClass: false,
  codeOnly: true,
  rows: [],
  report: null,
  activeCat: "all",
  selected: null,
  connKey: "idle",
  connCls: "",
  foot: { titleKey: "foot.idle", subKey: "foot.idleSub" },
  engineVer: null,
  sourceFile: null,
  output: null,
  outputGenerated: false,
};

let monacoEditor = null;
let monacoLoading = false;
const RING_C = 169.6;

function toast(message, isError) {
  const el = $("toast");
  el.textContent = message;
  el.classList.toggle("err", !!isError);
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (el.hidden = true), 2600);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text == null ? "" : String(text));
    toast(t("toast.copied"));
  } catch (e) {
    toast(String(e), true);
  }
}

function hideCtxMenu() {
  const m = $("ctx-menu");
  if (m) m.hidden = true;
}

function showCtxMenu(x, y, items) {
  const m = $("ctx-menu");
  if (!m) return;
  m.innerHTML = items
    .map((it) => (it.sep ? `<div class="ctx-sep"></div>` : `<button type="button">${esc(it.label)}</button>`))
    .join("");
  let bi = 0;
  const btns = m.querySelectorAll("button");
  items.forEach((it) => {
    if (it.sep) return;
    const b = btns[bi++];
    b.addEventListener("click", () => {
      hideCtxMenu();
      it.action();
    });
  });
  m.hidden = false;
  const mw = m.offsetWidth;
  const mh = m.offsetHeight;
  m.style.left = Math.max(8, Math.min(x, window.innerWidth - mw - 8)) + "px";
  m.style.top = Math.max(8, Math.min(y, window.innerHeight - mh - 8)) + "px";
}

document.addEventListener("click", (e) => {
  if (!(e.target.closest && e.target.closest("#ctx-menu"))) hideCtxMenu();
});
document.addEventListener("keydown", (e) => {
  if ((e.key || "") === "Escape") hideCtxMenu();
});
document.addEventListener("scroll", hideCtxMenu, true);
window.addEventListener("blur", hideCtxMenu);

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
// For values placed inside double-quoted HTML attributes (paths, AOBs, titles): also escape quotes.
function escAttr(s) {
  return esc(s).replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function hueOf(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return h % 360;
}
function catChip(category) {
  return `<span class="cat-chip" style="--ch:${hueOf(category)}">${esc(category)}</span>`;
}
function smartName(ext) {
  const r = state.report;
  const mod = ((r && r.module_name) || "offsets").replace(/\.exe$/i, "");
  const ver = r && r.build_version ? `-${r.build_version}` : "";
  const date = new Date().toISOString().slice(0, 10);
  return `${mod}${ver}-${date}.${ext}`;
}

let currentView = "workspace";
function showView(name) {
  currentView = name;
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${name}`));
  if (name === "patterns") refreshPatterns();
  if (name === "editor") ensureEditor();
  if (name === "history") loadHistory();
  if (name === "asmscan") asmSyncTarget();
  if (name === "sigmaker") renderSigFiles();
}
document.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
$("open-editor").addEventListener("click", () => showView("editor"));
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && (e.key === "f" || e.key === "F")) {
    if (currentView === "editor") return;
    const inp = $({ workspace: "w-search", patterns: "pattern-search", history: "hist-search", asmscan: "asm-search" }[currentView]);
    if (inp) {
      e.preventDefault();
      inp.focus();
      inp.select();
    }
  }
});

function currentWindow() {
  const tauri = window.__TAURI__ || {};
  if (tauri.window && tauri.window.getCurrentWindow) return tauri.window.getCurrentWindow();
  if (tauri.webviewWindow && tauri.webviewWindow.getCurrentWebviewWindow) return tauri.webviewWindow.getCurrentWebviewWindow();
  return null;
}
try {
  const appWindow = currentWindow();
  if (appWindow) {
    $("win-min").addEventListener("click", () => appWindow.minimize());
    $("win-max").addEventListener("click", () => appWindow.toggleMaximize());
    $("win-close").addEventListener("click", () => appWindow.close());
  }
} catch {
}

document.addEventListener("contextmenu", (e) => {
  if (!(e.target.closest && e.target.closest(".monaco-editor"))) e.preventDefault();
});
document.addEventListener("keydown", (e) => {
  const k = (e.key || "").toLowerCase();
  if (k === "f5" || ((e.ctrlKey || e.metaKey) && (k === "r" || k === "p"))) e.preventDefault();
});

let masked = false;

const FAKE_WORDS = ["Get", "Set", "Send", "Recv", "Make", "Init", "Update", "Player", "Skill", "Packet", "Mob", "Quest", "Field", "Stat", "Buff", "Item", "Inven", "Login", "Channel", "Hook", "Base", "Ctx", "Mgr", "Pool", "Node", "Data", "Calc", "Apply", "Reset", "Find"];
const FAKE_CATS = ["functions", "packets", "globals", "offsets", "structs", "hooks"];
const FAKE_NOTES = ["entry point", "inbound handler", "struct field", "opcode", "cached pointer", ""];
const MASK_KEYS = { "d-sig": "sig", "d-name": "name", "d-addr": "addr", "d-cat": "cat", "d-note": "note" };
const FIELD_CLASSES = ".d-sig, .d-name, .d-addr, .d-cat, .d-note";

function seedHash(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h = (h ^ s.charCodeAt(i)) >>> 0;
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0 || 1;
}
function rngFrom(seed) {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x;
  };
}
function fakeFor(kind, real) {
  if (kind === "d-addr" && !/0x/i.test(real)) return real;
  const rng = rngFrom(seedHash(real));
  const hex = "0123456789ABCDEF";
  if (kind === "d-name") {
    let s = "";
    for (let i = 0, n = 2 + (rng() % 2); i < n; i++) s += FAKE_WORDS[rng() % FAKE_WORDS.length];
    return s;
  }
  if (kind === "d-addr") {
    const m = real.match(/0x([0-9a-fA-F]+)/i);
    const len = m ? m[1].length : 6;
    let out = "";
    for (let i = 0; i < len; i++) out += hex[rng() % 16];
    return "0x" + out;
  }
  if (kind === "d-sig") {
    return real
      .trim()
      .split(/\s+/)
      .map((tok) => (tok.includes("?") ? "??" : hex[rng() % 16] + hex[rng() % 16]))
      .join(" ");
  }
  if (kind === "d-cat") return FAKE_CATS[rng() % FAKE_CATS.length];
  if (kind === "d-note") return real.trim() ? FAKE_NOTES[rng() % FAKE_NOTES.length] : "";
  return real;
}
function fieldKind(el) {
  return ["d-sig", "d-name", "d-addr", "d-cat", "d-note"].find((k) => el.classList.contains(k));
}
function randomizeActive() {
  return masked && state.maskMode === "randomize";
}
const maskObserver = new MutationObserver(() => applyRandomizeTo(document));
function applyRandomizeTo(root) {
  maskObserver.disconnect();
  root.querySelectorAll(FIELD_CLASSES).forEach((el) => {
    const kind = fieldKind(el);
    if (randomizeActive() && state.mask[MASK_KEYS[kind]]) {
      if (el.dataset.real == null) el.dataset.real = el.textContent;
      el.textContent = fakeFor(kind, el.dataset.real);
    } else if (el.dataset.real != null) {
      el.textContent = el.dataset.real;
      delete el.dataset.real;
    }
  });
  if (randomizeActive()) maskObserver.observe(document.body, { childList: true, subtree: true });
}

function applyMask() {
  const c = document.body.classList;
  c.toggle("masked", masked);
  c.toggle("mask-rand", randomizeActive());
  c.toggle("m-sig", state.mask.sig);
  c.toggle("m-name", state.mask.name);
  c.toggle("m-addr", state.mask.addr);
  c.toggle("m-cat", state.mask.cat);
  c.toggle("m-note", state.mask.note);
  c.toggle("m-editor", state.mask.editor);
  c.toggle("m-output", state.mask.output);
  applyRandomizeTo(document);
}

$("mask-toggle").addEventListener("click", () => {
  masked = !masked;
  const btn = $("mask-toggle");
  btn.classList.toggle("active", masked);
  btn.querySelector(".ico").innerHTML = ICONS[masked ? "eye-off" : "eye"];
  btn.title = t(masked ? "mask.on" : "mask.off");
  applyMask();
});

document.querySelectorAll("[data-mask]").forEach((cb) => {
  cb.checked = !!state.mask[cb.dataset.mask];
  cb.addEventListener("change", () => {
    state.mask[cb.dataset.mask] = cb.checked;
    saveMaskSettings();
    applyMask();
  });
});

const modeCb = $("mask-mode");
if (modeCb) {
  modeCb.checked = state.maskMode === "randomize";
  modeCb.addEventListener("change", () => {
    state.maskMode = modeCb.checked ? "randomize" : "blur";
    saveMaskMode();
    applyMask();
  });
}

applyMask();

$("t-arch").addEventListener("click", () => {
  state.arch = state.arch === "x64" ? "x86" : "x64";
  const on = state.arch === "x64";
  $("t-arch").classList.toggle("active", on);
  $("t-arch-label").textContent = on ? t("ws.arch64") : t("ws.arch32");
});
$("t-wait").addEventListener("click", () => {
  state.wait = !state.wait;
  $("t-wait").classList.toggle("active", state.wait);
});
$("t-class").addEventListener("click", () => {
  state.byClass = !state.byClass;
  $("t-class").classList.toggle("active", state.byClass);
  $("target-label").textContent = state.byClass ? t("ws.windowClass") : t("ws.targetProcess");
  $("w-target").placeholder = state.byClass ? t("ws.windowClassPh") : "MapleStory.exe";
});
$("t-code").addEventListener("click", () => {
  state.codeOnly = !state.codeOnly;
  $("t-code").classList.toggle("active", state.codeOnly);
});

function setConn(key, cls) {
  state.connKey = key;
  state.connCls = cls || "";
  $("conn-text").textContent = t(`conn.${key}`);
  $("conn-pill").className = `conn-pill ${cls || ""}`;
}

function setRing(mode, pct) {
  const ring = $("ring");
  if (mode === "run") {
    ring.classList.add("run");
    $("ring-text").textContent = "···";
    $("ring-fg").style.strokeDashoffset = RING_C * 0.25;
    return;
  }
  ring.classList.remove("run");
  const p = Math.max(0, Math.min(100, pct || 0));
  $("ring-fg").style.strokeDashoffset = RING_C * (1 - p / 100);
  $("ring-text").textContent = `${Math.round(p)}%`;
}

function setFoot(titleKey, subKey, params, rawSub) {
  state.foot = { titleKey, subKey, params, rawSub };
  $("foot-title").textContent = t(titleKey);
  $("foot-sub").textContent = subKey ? t(subKey, params) : rawSub || "";
}

function fmtMs(ms) {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
}

async function runScan() {
  const req = {
    locator: state.byClass ? "class" : "name",
    target: $("w-target").value.trim(),
    module: $("w-module").value.trim(),
    arch: state.arch,
    wait: state.wait,
    timeout_secs: $("w-timeout").value ? Number($("w-timeout").value) : null,
    code_only: state.codeOnly,
    patterns: state.patternText,
  };
  if (!req.target) {
    toast(t("toast.enterTarget"), true);
    return;
  }

  $("w-scan").disabled = true;
  $("w-stop").disabled = false;
  setConn(state.wait ? "waiting" : "scanning", state.wait ? "wait" : "run");
  setRing("run");
  setFoot(state.wait ? "foot.waiting" : "foot.scanning", state.wait ? "foot.waitingSub" : "foot.scanningSub");

  try {
    const report = await invoke("attach_and_scan", { req });
    state.report = report;
    state.rows = report.rows;
    state.activeCat = "all";
    state.selected = null;
    buildTabs();
    renderResults();
    autoSelect();

    const total = report.found + report.unresolved + report.not_found;
    $("s-found").textContent = report.found;
    $("s-unresolved").textContent = report.unresolved;
    $("s-time").textContent = fmtMs(report.elapsed_ms);
    $("s-module").textContent = report.module_name;
    setConn("attached", "ok");
    setRing("done", total ? (report.found / total) * 100 : 0);
    const mb = (report.bytes_scanned / 1048576).toFixed(0);
    const gbs = (report.scan_ms > 0 ? report.bytes_scanned / (report.scan_ms / 1000) / 1073741824 : 0).toFixed(2);
    setFoot("foot.complete", "foot.completeSub", { found: report.found, total, mb, gbs, attach: report.attach_ms });
  } catch (err) {
    setConn("error", "err");
    setRing("done", 0);
    setFoot("foot.failed", null, null, String(err));
    toast(String(err), true);
  } finally {
    $("w-scan").disabled = false;
    $("w-stop").disabled = true;
  }
}

$("w-scan").addEventListener("click", runScan);
$("w-stop").addEventListener("click", () => {
  invoke("cancel_scan");
  setConn("cancelled", "");
  setRing("done", 0);
  setFoot("foot.cancelled", "foot.cancelledSub");
});

const asmState = { report: null };

function asmSyncTarget() {
  const target = $("w-target").value.trim();
  const el = $("asm-target");
  if (!el) return;
  if (!target) {
    el.textContent = t("asm.noTarget");
    return;
  }
  const arch = state.arch === "x64" ? t("ws.arch64") : t("ws.arch32");
  el.textContent = t("asm.targetSummary", { target, module: $("w-module").value.trim() || target, arch });
}

async function runAsmScan() {
  const target = $("w-target").value.trim();
  if (!target) {
    toast(t("toast.enterTarget"), true);
    return;
  }
  const lines = $("asm-input").value;
  if (!lines.trim()) {
    toast(t("asm.needLines"), true);
    return;
  }
  const req = {
    locator: state.byClass ? "class" : "name",
    target,
    module: $("w-module").value.trim(),
    arch: state.arch,
    wait: state.wait,
    timeout_secs: $("w-timeout").value ? Number($("w-timeout").value) : null,
    code_only: state.codeOnly,
    from: $("asm-from").value.trim() || null,
    to: $("asm-to").value.trim() || null,
    lines,
  };
  $("asm-scan").disabled = true;
  $("asm-stop").disabled = false;
  $("asm-count").textContent = t("asm.running");
  try {
    const report = await invoke("assembly_scan", { req });
    asmState.report = report;
    renderAsmResults(report);
  } catch (err) {
    asmState.report = null;
    $("asm-count").textContent = "";
    $("asm-results").innerHTML = `<div class="insp-hint">${esc(String(err))}</div>`;
    toast(String(err), true);
  } finally {
    $("asm-scan").disabled = false;
    $("asm-stop").disabled = true;
  }
}

function renderAsmResults(report) {
  $("asm-count").textContent =
    (report.total === 1 ? t("asm.matchOne") : t("asm.match", { n: report.total })) +
    (report.truncated ? " · " + t("asm.truncated", { shown: report.hits.length, total: report.total }) : "");
  const host = $("asm-results");
  if (!report.hits.length) {
    host.innerHTML = `<div class="insp-hint">${t("asm.none")}</div>`;
    return;
  }
  const term = ($("asm-search").value || "").trim().toLowerCase();
  const hits = term
    ? report.hits.filter((h) => h.address.toLowerCase().includes(term) || h.lines.join(" ").toLowerCase().includes(term))
    : report.hits;
  host.innerHTML = hits
    .map(
      (h) =>
        `<div class="asm-hit"><div class="asm-hit-head"><span class="mono d-addr">${esc(h.address)}</span><span class="asm-rva muted">+${esc(h.rva)}</span><button class="icon-btn asm-save" data-bytes="${esc(h.bytes)}">${esc(t("asm.save"))}</button></div><pre class="asm-lines mono">${h.lines.map(esc).join("\n")}</pre></div>`,
    )
    .join("");
  host.querySelectorAll(".asm-save").forEach((b) => b.addEventListener("click", () => asmSaveAsPattern(b.dataset.bytes)));
}

function asmSaveAsPattern(bytes) {
  openModal(-1);
  $("f-aob").value = bytes;
  $("f-name").focus();
}

$("asm-scan").addEventListener("click", runAsmScan);
$("asm-stop").addEventListener("click", () => invoke("cancel_scan"));
$("asm-search").addEventListener("input", () => {
  if (asmState.report) renderAsmResults(asmState.report);
});

const sigState = { files: [], negatives: [], response: null, mode: "aob", cross: "separate", showJson: false, alertDismissed: false };

function renderSigFiles() {
  const host = $("sig-files");
  if (!host) return;
  if (!sigState.files.length) {
    host.innerHTML = `<span class="muted">${esc(t("sig.noFiles"))}</span>`;
  } else {
    host.innerHTML = sigState.files
      .map((f) => {
        const tip = escAttr(
          `entropy ${(f.max_entropy || 0).toFixed(2)}${f.reasons.length ? " · " + f.reasons.join("; ") : ""}`,
        );
        const badge = f.packed
          ? `<span class="sig-badge packed" title="${tip}">${t("sig.packed")}</span>`
          : `<span class="sig-badge ok" title="${tip}">${t("sig.unpacked")}</span>`;
        return `<span class="sig-chip"><span class="d-name">${esc(f.name)}</span><span class="muted">${esc(f.arch)}</span>${badge}<button class="sig-chip-x" data-rm="${escAttr(f.path)}" title="remove">✕</button></span>`;
      })
      .join("");
    host.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => sigRemoveFile(b.dataset.rm)));
  }
  const sel = $("sig-ref");
  if (sel) sel.innerHTML = sigState.files.map((f) => `<option value="${escAttr(f.path)}">${esc(f.name)}</option>`).join("");
  const anyPacked = sigState.files.some((f) => f.packed);
  const alert = $("sig-alert");
  if (anyPacked && !sigState.alertDismissed) {
    alert.hidden = false;
    alert.innerHTML = `<span>⚠ ${esc(t("sig.packedAlert"))}</span><button class="sig-alert-x" title="${escAttr(t("sig.dismiss"))}">✕</button>`;
    const x = alert.querySelector(".sig-alert-x");
    if (x)
      x.addEventListener("click", () => {
        sigState.alertDismissed = true;
        alert.hidden = true;
      });
  } else {
    alert.hidden = true;
  }
}

async function sigPickFiles() {
  let paths;
  try {
    paths = await invoke("pick_open_files");
  } catch {
    return;
  }
  for (const p of paths) {
    if (sigState.files.some((f) => f.path === p)) continue;
    try {
      const info = await invoke("inspect_pe", { path: p });
      sigState.files.push({
        path: p,
        name: info.name,
        arch: info.arch,
        packed: info.packed,
        reasons: info.reasons,
        max_entropy: info.max_entropy,
      });
    } catch (e) {
      toast(String(e), true);
    }
  }
  sigState.alertDismissed = false;
  renderSigFiles();
  sigUpdateValidity();
}

function sigRemoveFile(path) {
  sigState.files = sigState.files.filter((f) => f.path !== path);
  sigState.alertDismissed = false;
  renderSigFiles();
  sigUpdateValidity();
}

function renderSigNegatives() {
  const host = $("sig-negatives");
  if (!host) return;
  if (!sigState.negatives.length) {
    host.innerHTML = "";
    return;
  }
  host.innerHTML = `<span class="muted">${esc(t("sig.negatives"))}:</span> ` +
    sigState.negatives
      .map((n) => `<span class="sig-chip"><span class="d-name">${esc(n.name)}</span><button class="sig-chip-x" data-rmneg="${escAttr(n.path)}" title="remove">✕</button></span>`)
      .join("");
  host.querySelectorAll("[data-rmneg]").forEach((b) => b.addEventListener("click", () => sigRemoveNegative(b.dataset.rmneg)));
}

async function sigPickNegatives() {
  let paths;
  try {
    paths = await invoke("pick_open_files");
  } catch {
    return;
  }
  for (const p of paths) {
    if (sigState.negatives.some((n) => n.path === p)) continue;
    sigState.negatives.push({ path: p, name: p.split(/[\\/]/).pop() || p });
  }
  renderSigNegatives();
}

function sigRemoveNegative(path) {
  sigState.negatives = sigState.negatives.filter((n) => n.path !== path);
  renderSigNegatives();
}

function sigSetMode(mode) {
  sigState.mode = mode;
  $("sig-mode-tabs")
    .querySelectorAll(".tab")
    .forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  $("sig-aob-row").hidden = !(mode === "aob" || mode === "both");
  $("sig-ref-row").hidden = !(mode === "ref" || mode === "both");
  $("sig-both-opts").hidden = mode !== "both";
  sigUpdateValidity();
}

function sigSetCross(mode) {
  sigState.cross = mode;
  $("sig-cross-toggle")
    .querySelectorAll(".seg-btn")
    .forEach((b) => b.classList.toggle("active", b.dataset.cross === mode));
  const hint = $("sig-cross-hint");
  const key = mode === "cross" ? "sig.crossHint" : "sig.separateHint";
  hint.setAttribute("data-i18n", key);
  hint.textContent = t(key);
  sigUpdateValidity();
}

function sigLines(id) {
  return $(id)
    .value.split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

const SIG_RVA_RE = /^(0x)?[0-9a-fA-F]+$/;
function sigRvaValidity() {
  const lines = sigLines("sig-rva");
  const bad = lines.length > 0 && lines.some((l) => !SIG_RVA_RE.test(l));
  $("sig-rva").classList.toggle("invalid", bad);
  return lines.length > 0 && !bad;
}

function sigUpdateValidity() {
  const m = sigState.mode;
  const hasFiles = sigState.files.length > 0;
  const aobOk = sigLines("sig-aob").length > 0;
  const rvaOk = sigRvaValidity();
  let ok = hasFiles;
  if (m === "aob") ok = ok && aobOk;
  else if (m === "ref") ok = ok && rvaOk;
  else if (sigState.cross === "cross") ok = ok && aobOk && rvaOk;
  else ok = ok && (aobOk || rvaOk);
  $("sig-gen").disabled = !ok;
}

function buildSigJobs() {
  const m = sigState.mode;
  const refPath = $("sig-ref").value;
  const aobs = sigLines("sig-aob");
  const rvas = sigLines("sig-rva");
  const jobs = [];
  if (m === "aob") {
    for (const sig of aobs) jobs.push({ type: "aob", sig });
  } else if (m === "ref") {
    for (const rva of rvas) jobs.push({ type: "ref", ref_path: refPath, rva });
  } else if (sigState.cross === "cross") {
    const n = Math.min(aobs.length, rvas.length);
    for (let i = 0; i < n; i++) jobs.push({ type: "cross", sig: aobs[i], ref_path: refPath, rva: rvas[i] });
  } else {
    for (const sig of aobs) jobs.push({ type: "aob", sig });
    for (const rva of rvas) jobs.push({ type: "ref", ref_path: refPath, rva });
  }
  return jobs;
}

let sigLoadTarget = null;
function sigLoadFile(targetId) {
  sigLoadTarget = targetId;
  $("sig-file-input").click();
}

function sigPhaseText(p) {
  const key = p && SIG_STAGE_KEY[p.phase];
  const base = key ? t(key, { label: p.label || "", index: p.index || 0, total: p.total || 0 }) : t("sig.generating");
  if (p && p.jobs > 1 && p.job > 0) return t("sig.jobProgress", { job: p.job, jobs: p.jobs }) + " " + base;
  return base;
}

async function runSigGen() {
  if (!sigState.files.length) {
    toast(t("sig.noFiles"), true);
    return;
  }
  const jobs = buildSigJobs();
  if (!jobs.length) {
    toast(sigState.mode === "ref" ? t("sig.needRva") : t("sig.needAob"), true);
    return;
  }
  if (sigState.mode === "both" && sigState.cross === "cross") {
    const a = sigLines("sig-aob").length;
    const r = sigLines("sig-rva").length;
    if (a !== r) toast(t("sig.crossUneven", { sigs: a, rvas: r }));
  }
  const req = { clients: sigState.files.map((f) => f.path), jobs, negatives: sigState.negatives.map((n) => n.path) };
  $("sig-gen").disabled = true;
  const setStatus = (msg) => {
    $("sig-results").innerHTML = `<div class="insp-hint">${esc(msg)}</div>`;
  };
  setStatus(t("sig.generating"));
  let unlisten = null;
  const ev = (window.__TAURI__ || {}).event;
  if (ev && ev.listen) {
    try {
      unlisten = await ev.listen("sig-progress", (e) => setStatus(sigPhaseText(e.payload)));
    } catch (_) {
      unlisten = null;
    }
  }
  try {
    sigState.response = await invoke("generate_signature", { req });
    if (unlisten) {
      unlisten();
      unlisten = null;
    }
    sigState.showJson = false;
    $("sig-json").hidden = false;
    renderSigResults();
  } catch (e) {
    sigState.response = null;
    $("sig-json").hidden = true;
    setStatus(String(e));
    toast(String(e), true);
  } finally {
    if (unlisten) unlisten();
    sigUpdateValidity();
  }
}

function gradeDesc(letter) {
  return t("sig.grade" + String(letter).toUpperCase());
}

function sigCandCard(c, tag, primary) {
  const grade = c.grade.toLowerCase();
  const rows = c.per_version
    .map(
      (p) =>
        `<tr><td class="d-name">${esc(p.label)}</td><td class="mono d-addr">${esc(p.match_rva || "-")}</td><td class="mono d-addr">${esc(p.resolved_target_rva || "-")}</td><td>${esc(p.target_type || "-")}</td></tr>`,
    )
    .join("");
  const diags = c.diags.length
    ? `<ul class="sig-diags">${c.diags.map((d) => `<li>${esc(d)}</li>`).join("")}</ul>`
    : "";
  return `<div class="sig-cand${primary ? " primary" : ""}">
    <div class="sig-cand-head">
      <span class="sig-grade g-${grade}" title="${escAttr(gradeDesc(c.grade))}">${esc(c.grade)}</span>
      ${tag ? `<span class="sig-tag">${esc(tag)}</span>` : ""}
      <span class="sig-aob mono d-sig">${esc(c.aob)}${esc(c.suffix)}</span>
      <span class="sig-actions">
        <button class="icon-btn sig-copy" data-aob="${escAttr(c.aob)}">${esc(t("sig.copy"))}</button>
        <button class="icon-btn sig-save" data-aob="${escAttr(c.aob)}" data-suffix="${escAttr(c.suffix)}">${esc(t("sig.save"))}</button>
      </span>
    </div>
    <div class="sig-stats muted">${t("sig.bytesFixed", { bytes: c.bytes, fixed: c.fixed, wild: c.wildcards, ratio: c.fixed_ratio.toFixed(2) })}${c.reloc_safe ? "" : " · ⚠ reloc"}</div>
    <table class="grid-table sig-pv"><thead><tr><th>${esc(t("sig.colVersion"))}</th><th>${esc(t("sig.colMatch"))}</th><th>${esc(t("sig.colTarget"))}</th><th>${esc(t("col.type"))}</th></tr></thead><tbody>${rows}</tbody></table>
    ${diags}
  </div>`;
}

function reportInnerHtml(r) {
  const anyPacked = r.inputs.some((i) => i.packed);
  let html = `<div class="sig-summary">${esc(t("sig.summary", { arch: r.arch, files: r.inputs.length, builds: r.unique_builds }))}${anyPacked ? ` · ⚠ ${esc(t("sig.packed"))}` : ""}</div>`;
  const dups = r.duplicate_groups.filter((g) => g[1].length > 1);
  if (dups.length) {
    html += `<div class="sig-section-h">${t("sig.dupBuilds")}</div>`;
    html += dups
      .map(
        (g) =>
          `<div class="sig-dup"><span class="sig-dup-hash mono">${esc(g[0])}</span><span class="muted">${esc(g[1].join(", "))}</span></div>`,
      )
      .join("");
  }
  html += r.chosen ? sigCandCard(r.chosen, t("sig.chosen"), true) : `<div class="insp-hint">${t("sig.none")}</div>`;
  if (r.alternates.length) {
    html += `<div class="sig-section-h">${t("sig.alternates")}</div>` + r.alternates.map((c) => sigCandCard(c, "", false)).join("");
  }
  if (r.rejected.length) {
    html += `<div class="sig-section-h">${t("sig.rejected")}</div>` + r.rejected.map((c) => sigCandCard(c, "", false)).join("");
  }
  if (r.diagnostics.length) {
    html += `<div class="sig-section-h">${t("sig.diagnostics")}</div><ul class="sig-diags">` + r.diagnostics.map((d) => `<li>${esc(d)}</li>`).join("") + "</ul>";
  }
  if (r.holdout && r.holdout.length) {
    const passed = r.holdout.filter((h) => h.matched).length;
    html += `<div class="sig-section-h">${t("sig.holdout")} (${passed}/${r.holdout.length})</div><ul class="sig-diags">` +
      r.holdout
        .map((h) => {
          const verdict = h.matched ? t("sig.holdoutOk") : h.generated ? t("sig.holdoutMiss") : t("sig.holdoutNone");
          return `<li class="sig-holdout ${h.matched ? "ok" : "bad"}"><span class="mono">${esc(h.held_out)}</span> ${esc(verdict)}</li>`;
        })
        .join("") +
      "</ul>";
  }
  if (r.string_anchor) {
    html += `<div class="sig-section-h">${t("sig.stringAnchor")}</div>` +
      `<div class="sig-anchor"><code class="mono">${esc(r.string_anchor)}</code><button class="icon-btn sig-copy" data-aob="${escAttr(r.string_anchor)}" title="${escAttr(t("sig.copy"))}">⧉</button></div>` +
      `<div class="insp-hint">${esc(t("sig.stringAnchorHint"))}</div>`;
  }
  if (r.negative_hits && r.negative_hits.length) {
    html += `<div class="sig-section-h">${t("sig.negHits")} (${r.negative_hits.length})</div><ul class="sig-diags">` +
      r.negative_hits
        .map((h) => `<li class="sig-holdout bad"><span class="mono">${esc(h.label)}</span> ${esc(t("sig.negHitCount", { n: h.count }))}</li>`)
        .join("") +
      "</ul>";
  }
  return html;
}

function gradeLegendHtml() {
  return (
    `<div class="sig-section-h">${t("sig.gradeLegend")}</div><ul class="sig-legend">` +
    ["A", "B", "C", "D", "F"].map((g) => `<li><span class="sig-grade g-${g.toLowerCase()}">${g}</span><span>${esc(gradeDesc(g))}</span></li>`).join("") +
    "</ul>"
  );
}

function crossVerdictHtml(c) {
  if (c.agrees) {
    return `<div class="sig-cross-verdict ok">✓ ${esc(t("sig.crossOk", { rva: c.expected_rva }))}</div>`;
  }
  return `<div class="sig-cross-verdict bad">✗ ${esc(t("sig.crossMismatch", { got: c.matched_rva || t("sig.crossNoMatch"), expected: c.expected_rva }))}</div>`;
}

function wireSigButtons(host) {
  host.querySelectorAll(".sig-copy").forEach((b) =>
    b.addEventListener("click", async () => {
      await navigator.clipboard.writeText(b.dataset.aob);
      toast(t("toast.copied"));
    }),
  );
  host.querySelectorAll(".sig-save").forEach((b) => b.addEventListener("click", () => sigSaveAsPattern(b.dataset.aob, b.dataset.suffix)));
}

function renderSigResults() {
  const host = $("sig-results");
  const resp = sigState.response;
  if (!resp) return;
  if (sigState.showJson) {
    host.innerHTML = `<pre class="sig-jsonview mono">${esc(JSON.stringify(resp, null, 2))}</pre>`;
    return;
  }
  const jobs = resp.jobs || [];
  if (!jobs.length) {
    host.innerHTML = `<div class="insp-hint">${t("sig.none")}</div>`;
    return;
  }
  const multi = jobs.length > 1;
  let html = "";
  jobs.forEach((job, i) => {
    const framed = multi || !!job.cross;
    html += `<div class="sig-job${framed ? " framed" : ""}">`;
    if (framed) {
      const chosen = job.report && job.report.chosen;
      const gradeChip = chosen ? `<span class="sig-grade g-${chosen.grade.toLowerCase()}" title="${escAttr(gradeDesc(chosen.grade))}">${esc(chosen.grade)}</span>` : "";
      html += `<div class="sig-job-head">${multi ? `<span class="sig-job-n">#${i + 1}</span>` : ""}<span class="sig-job-label mono">${esc(job.label)}</span>${gradeChip}</div>`;
    }
    if (job.error) {
      html += `<div class="sig-job-err">${esc(job.error)}</div>`;
    } else {
      if (job.cross) html += crossVerdictHtml(job.cross);
      if (job.report) html += reportInnerHtml(job.report);
    }
    html += `</div>`;
  });
  html += gradeLegendHtml();
  host.innerHTML = html;
  wireSigButtons(host);
}

function sigSaveAsPattern(aob, suffix) {
  // The resolver keys off the pattern-name suffix (_PTR/_CALL/_OFF/_HDR). Kind::Call follows both
  // call and jmp rel32, so a _JMP anchor is saved as _CALL so the scanner resolves it to its target.
  const nameSuffix = suffix === "_JMP" ? "_CALL" : suffix;
  openModal(-1);
  $("f-aob").value = aob;
  $("f-name").value = "NewSig" + nameSuffix;
  $("f-name").focus();
}

$("sig-pick").addEventListener("click", sigPickFiles);
$("sig-pick-neg").addEventListener("click", sigPickNegatives);
$("sig-gen").addEventListener("click", runSigGen);
$("sig-json").addEventListener("click", () => {
  sigState.showJson = !sigState.showJson;
  renderSigResults();
});
$("sig-mode-tabs")
  .querySelectorAll(".tab")
  .forEach((b) => b.addEventListener("click", () => sigSetMode(b.dataset.mode)));
$("sig-cross-toggle")
  .querySelectorAll(".seg-btn")
  .forEach((b) => b.addEventListener("click", () => sigSetCross(b.dataset.cross)));
["sig-aob", "sig-rva"].forEach((id) => {
  const ta = $(id);
  ta.addEventListener("input", sigUpdateValidity);
  ta.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      if (!$("sig-gen").disabled) runSigGen();
    }
  });
});
document.querySelectorAll(".sig-load").forEach((b) => b.addEventListener("click", () => sigLoadFile(b.dataset.target)));
$("sig-file-input").addEventListener("change", (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file || !sigLoadTarget) {
    e.target.value = "";
    return;
  }
  const target = sigLoadTarget;
  const reader = new FileReader();
  reader.onload = () => {
    const ta = $(target);
    const incoming = String(reader.result || "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    const existing = ta.value
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    ta.value = existing.concat(incoming).join("\n");
    sigUpdateValidity();
    toast(t("sig.loadedLines", { n: incoming.length }));
  };
  reader.readAsText(file);
  e.target.value = "";
});
sigUpdateValidity();

function buildTabs() {
  const cats = [...new Set(state.rows.map((r) => r.category))].sort();
  const host = $("w-tabs");
  host.innerHTML =
    `<button class="tab ${state.activeCat === "all" ? "active" : ""}" data-cat="all">${esc(t("ws.tabAll"))}</button>` +
    cats
      .map((c) => `<button class="tab ${state.activeCat === c ? "active" : ""}" data-cat="${esc(c)}">${esc(c)}</button>`)
      .join("");
  host.querySelectorAll(".tab").forEach((tabEl) =>
    tabEl.addEventListener("click", () => {
      state.activeCat = tabEl.dataset.cat;
      buildTabs();
      renderResults();
    })
  );
}

function accentClass(row) {
  if (row.status !== "found") return "dot-muted";
  return row.type === "call" || row.type === "header" ? "dot-violet" : "dot-blue";
}

function typeKey(kind) {
  return { pointer: "type.pointer", call: "type.function", offset: "type.offset", header: "type.header", direct: "type.address" }[kind];
}
function typeLabel(kind) {
  const key = typeKey(kind);
  return key ? t(key) : kind;
}

function statusClass(status) {
  return status === "not found" ? "notfound" : status;
}
function statusText(status) {
  return status === "found" ? t("status.found") : status === "unresolved" ? t("status.unresolved") : t("status.notFound");
}
function statusBadge(status) {
  return `<span class="badge ${statusClass(status)}">${esc(statusText(status))}</span>`;
}

function renderResults() {
  const term = $("w-search").value.trim().toLowerCase();
  const body = $("w-body");
  const maxHits = Math.max(1, ...state.rows.map((r) => r.matches));
  const n = state.rows.length;
  $("w-count").textContent = t(n === 1 ? "res.countOne" : "res.count", { n });

  const rows = state.rows.filter((r) => {
    if (state.activeCat !== "all" && r.category !== state.activeCat) return false;
    if (!term) return true;
    return (
      r.name.toLowerCase().includes(term) ||
      (r.value || "").toLowerCase().includes(term) ||
      r.category.toLowerCase().includes(term)
    );
  });

  if (rows.length === 0) {
    body.innerHTML = `<tr class="empty"><td colspan="6">${esc(state.rows.length ? t("ws.emptyFilter") : t("ws.empty"))}</td></tr>`;
    return;
  }

  body.innerHTML = rows
    .map((r) => {
      const pct = (r.matches / maxHits) * 100;
      const value = r.value ? `<span class="mono d-addr">${r.value}</span>` : '<span class="muted"></span>';
      return `<tr data-name="${esc(r.name)}" class="${state.selected === r.name ? "selected" : ""}">
        <td><div class="name-cell"><span class="dot-acc ${accentClass(r)}"></span>
          <div><div class="name-main d-name">${esc(r.name)}</div><div class="name-sub d-cat">${esc(r.category)}</div></div></div></td>
        <td>${value}</td>
        <td><span class="sig d-sig" title="${esc(r.pattern)}">${esc(r.pattern)}</span></td>
        <td>${statusBadge(r.status)}</td>
        <td><span class="tag">${esc(typeLabel(r.type))}</span></td>
        <td><div class="hits"><div class="bar"><span style="width:${pct}%"></span></div><span class="num">${r.matches}</span></div></td>
      </tr>`;
    })
    .join("");

  body.querySelectorAll("tr[data-name]").forEach((tr) => tr.addEventListener("click", () => selectRow(tr.dataset.name)));
}

function autoSelect() {
  const first = state.rows.find((r) => r.status === "found") || state.rows[0];
  if (first) selectRow(first.name);
}

function absAddress(row) {
  if (!row.value || row.is_offset || !state.report) return null;
  try {
    return "0x" + (BigInt(state.report.module_base) + BigInt(row.value)).toString(16).toUpperCase();
  } catch {
    return null;
  }
}

function selectRow(name) {
  const row = state.rows.find((r) => r.name === name);
  if (!row) return;
  state.selected = name;
  document.querySelectorAll("#w-body tr").forEach((tr) => tr.classList.toggle("selected", tr.dataset.name === name));

  $("insp-name").textContent = row.name;
  const sb = $("insp-status");
  sb.className = `badge ${statusClass(row.status)}`;
  sb.textContent = statusText(row.status);
  $("insp-desc").textContent = `${typeLabel(row.type)} · ${row.category}`;
  $("insp-hint").hidden = true;
  $("insp-body").hidden = false;

  const abs = absAddress(row);
  $("insp-rva").textContent = row.value || "";
  $("insp-abs").textContent = abs || (row.is_offset ? t("insp.displacement") : "");
  $("insp-aob").textContent = row.pattern;
  $("insp-type").textContent = typeLabel(row.type);
  $("insp-cat").textContent = row.category;
  $("insp-mod").textContent = state.report ? state.report.module_name : "";

  const maxHits = Math.max(1, ...state.rows.map((r) => r.matches));
  $("insp-bar").style.width = `${(row.matches / maxHits) * 100}%`;
  $("insp-hits").textContent = `${row.matches}`;
  $("insp-note").textContent = row.note || t("insp.noNotes");

  const copy = $("insp-copy");
  copy.disabled = !row.value;
  copy.onclick = async () => {
    await navigator.clipboard.writeText(abs || row.value || "");
    toast(t("toast.addressCopied"));
  };
}

$("w-search").addEventListener("input", renderResults);
$("w-source-btn").addEventListener("click", async () => {
  const path = await invoke("pick_open_file");
  if (!path) return;
  try {
    state.patternText = await invoke("read_text_file", { path });
    syncEditor();
    await reparse();
    state.sourceFile = path.split(/[\\/]/).pop();
    $("w-source").value = state.sourceFile;
    toast(t("toast.loadedN", { n: state.patterns.length }));
  } catch (err) {
    toast(String(err), true);
  }
});

const EXPORT_KEY = { header: "ws.exportHeader", ce: "ws.exportCe", txt: "ws.exportTxt" };

$("w-export").addEventListener("click", (e) => {
  e.stopPropagation();
  $("export-menu").hidden = !$("export-menu").hidden;
});
document.addEventListener("click", () => ($("export-menu").hidden = true));
document.querySelectorAll("#export-menu button").forEach((b) =>
  b.addEventListener("click", async () => {
    try {
      const text = await invoke("export_text", { format: b.dataset.export });
      $("output-text").textContent = text;
      state.outputGenerated = true;
      state.output = { typeKey: EXPORT_KEY[b.dataset.export], n: text.split("\n").length };
      $("output-label").textContent = t("out.label", { name: t(state.output.typeKey), n: state.output.n });
      $("output-text").dataset.suggest = smartName(
        b.dataset.export === "header" ? "h" : b.dataset.export === "ce" ? "CT" : "txt",
      );
      showView("output");
    } catch (err) {
      toast(String(err), true);
    }
  })
);

$("out-copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("output-text").textContent);
  toast(t("toast.copied"));
});
$("out-save").addEventListener("click", async () => {
  const path = await invoke("pick_save_file", { defaultName: $("output-text").dataset.suggest || "output.txt" });
  if (!path) return;
  try {
    await invoke("write_text_file", { path, contents: $("output-text").textContent });
    toast(t("toast.saved", { path }));
  } catch (err) {
    toast(String(err), true);
  }
});

async function reparse() {
  state.patterns = await invoke("parse_patterns_text", { text: state.patternText, arch: state.arch });
  $("s-loaded").textContent = state.patterns.length;
}

function refreshPatterns() {
  reparse().then(renderPatterns);
}

function patternMatches(p, term, cat) {
  if (cat !== "all" && p.category !== cat) return false;
  if (!term) return true;
  return (
    p.name.toLowerCase().includes(term) ||
    p.aob.toLowerCase().includes(term) ||
    (p.note || "").toLowerCase().includes(term)
  );
}

function filteredPatterns() {
  const term = $("pattern-search").value.trim().toLowerCase();
  const cat = $("pattern-cat").value || "all";
  return state.patterns.filter((p) => patternMatches(p, term, cat));
}

function patternRecord(p) {
  return { name: p.name, type: typeLabel(p.type), category: p.category, signature: p.aob, note: p.note || "" };
}

function patternLine(p) {
  return `${p.name} = ${p.aob}${p.note ? ` ; ${p.note}` : ""}`;
}

function patternCtxItems(p) {
  return [
    { label: t("ctx.copyName"), action: () => copyText(p.name) },
    { label: t("ctx.copyType"), action: () => copyText(typeLabel(p.type)) },
    { label: t("ctx.copyCategory"), action: () => copyText(p.category) },
    { label: t("ctx.copySignature"), action: () => copyText(p.aob) },
    { label: t("ctx.copyNote"), action: () => copyText(p.note || "") },
    { sep: true },
    { label: t("ctx.copyJson"), action: () => copyText(JSON.stringify(patternRecord(p), null, 2)) },
    { label: t("ctx.copyText"), action: () => copyText(patternLine(p)) },
    { sep: true },
    { label: t("ctx.copyAllJson"), action: () => copyText(JSON.stringify(filteredPatterns().map(patternRecord), null, 2)) },
    { label: t("ctx.copyAllText"), action: () => copyText(filteredPatterns().map(patternLine).join("\n")) },
  ];
}

function renderPatterns() {
  const n = state.patterns.length;
  $("pattern-count").textContent = t(n === 1 ? "pat.countOne" : "pat.count", { n });
  const sel = $("pattern-cat");
  const current = sel.value || "all";
  const cats = [...new Set(state.patterns.map((p) => p.category))].sort();
  sel.innerHTML =
    `<option value="all">${esc(t("pat.allCategories"))}</option>` +
    cats.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  sel.value = [...sel.options].some((o) => o.value === current) ? current : "all";

  const term = $("pattern-search").value.trim().toLowerCase();
  const cat = sel.value;
  const body = $("pattern-body");
  const rows = state.patterns.map((p, i) => ({ p, i })).filter(({ p }) => patternMatches(p, term, cat));

  if (rows.length === 0) {
    body.innerHTML = `<tr class="empty"><td colspan="6">${esc(t("pat.empty"))}</td></tr>`;
    return;
  }

  body.innerHTML = rows
    .map(
      ({ p, i }) => `<tr data-pi="${i}">
      <td class="mono d-name">${esc(p.name)}</td>
      <td><span class="tag">${esc(typeLabel(p.type))}</span></td>
      <td class="d-cat">${esc(p.category)}</td>
      <td><span class="sig d-sig copyable" title="${escAttr(p.aob)}" data-aob="${escAttr(p.aob)}">${esc(p.aob)}</span></td>
      <td class="note-cell d-note">${esc(p.note || "")}</td>
      <td><div class="row-actions">
        <button class="icon-btn" data-edit="${i}">${esc(t("pat.edit"))}</button>
        <button class="icon-btn danger" data-del="${i}">${esc(t("pat.del"))}</button>
      </div></td></tr>`
    )
    .join("");
  body.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => openModal(Number(b.dataset.edit))));
  body.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", () => deletePattern(Number(b.dataset.del))));
  body.querySelectorAll(".sig.copyable").forEach((el) => el.addEventListener("click", () => copyText(el.dataset.aob)));
  body.querySelectorAll("tr[data-pi]").forEach((tr) =>
    tr.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      const p = state.patterns[Number(tr.dataset.pi)];
      if (p) showCtxMenu(e.clientX, e.clientY, patternCtxItems(p));
    })
  );
}

function regenerate(patterns) {
  const groups = new Map();
  for (const p of patterns) {
    const cat = (p.category || "globals").trim() || "globals";
    if (!groups.has(cat)) groups.set(cat, []);
    groups.get(cat).push(p);
  }
  const lines = [];
  for (const [cat, items] of groups) {
    lines.push(`[${cat}]`);
    for (const p of items) lines.push(`${p.name} = ${p.aob}${p.note && p.note.trim() ? `   ; ${p.note.trim()}` : ""}`);
    lines.push("");
  }
  return lines.join("\n").trimEnd() + "\n";
}

async function commitPatterns(patterns) {
  state.patternText = regenerate(patterns);
  syncEditor();
  await reparse();
  renderPatterns();
}

function deletePattern(index) {
  commitPatterns(state.patterns.filter((_, i) => i !== index));
  toast(t("toast.deleted"));
}

$("pattern-search").addEventListener("input", renderPatterns);
$("pattern-cat").addEventListener("change", renderPatterns);
$("pat-add").addEventListener("click", () => openModal(-1));
$("pat-load").addEventListener("click", async () => {
  const path = await invoke("pick_open_file");
  if (!path) return;
  try {
    state.patternText = await invoke("read_text_file", { path });
    state.sourceFile = path.split(/[\\/]/).pop();
    $("w-source").value = state.sourceFile;
    syncEditor();
    await reparse();
    renderPatterns();
    toast(t("toast.loadedN", { n: state.patterns.length }));
  } catch (err) {
    toast(String(err), true);
  }
});
$("pat-save").addEventListener("click", async () => {
  const path = await invoke("pick_save_file", { defaultName: "patterns.txt" });
  if (!path) return;
  try {
    const body = path.toLowerCase().endsWith(".json")
      ? JSON.stringify({ arch: state.arch, patterns: state.patterns }, null, 2)
      : state.patternText;
    await invoke("write_text_file", { path, contents: body });
    toast(t("toast.saved", { path }));
  } catch (err) {
    toast(String(err), true);
  }
});

function openModal(index) {
  state.editingIndex = index;
  const p = index >= 0 ? state.patterns[index] : null;
  $("modal-title").textContent = p ? t("modal.edit") : t("modal.add");
  $("f-name").value = p ? p.name : "";
  $("f-cat").value = p ? p.category : "";
  $("f-aob").value = p ? p.aob : "";
  $("f-note").value = p ? p.note : "";
  $("modal").hidden = false;
  $("f-name").focus();
}
function closeModal() {
  $("modal").hidden = true;
}
$("modal-cancel").addEventListener("click", closeModal);
$("modal").addEventListener("click", (e) => {
  if (e.target.id === "modal") closeModal();
});
$("modal-ok").addEventListener("click", async () => {
  const name = $("f-name").value.trim();
  const aob = $("f-aob").value.trim();
  if (!name || !aob) {
    toast(t("toast.nameAobRequired"), true);
    return;
  }
  const entry = { name, category: $("f-cat").value.trim() || "globals", aob, note: $("f-note").value.trim() };
  const next = state.patterns.slice();
  if (state.editingIndex >= 0) next[state.editingIndex] = entry;
  else next.push(entry);
  const wasEdit = state.editingIndex >= 0;
  closeModal();
  await commitPatterns(next);
  toast(wasEdit ? t("toast.updated") : t("toast.added"));
});

window.MonacoEnvironment = {
  getWorkerUrl() {
    return "vs/base/worker/workerMain.js";
  },
};

function ensureEditor() {
  if (monacoEditor) {
    monacoEditor.layout();
    return;
  }
  if (monacoLoading) return;
  monacoLoading = true;
  $("editor-host").innerHTML = `<div style="padding:18px;color:#64748b">${esc(t("ed.loading"))}</div>`;
  require.config({ paths: { vs: "vs" } });
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

$("ed-load").addEventListener("click", async () => {
  const path = await invoke("pick_open_file");
  if (!path) return;
  try {
    state.patternText = await invoke("read_text_file", { path });
    state.sourceFile = path.split(/[\\/]/).pop();
    $("w-source").value = state.sourceFile;
    syncEditor();
    toast(t("toast.loaded"));
  } catch (err) {
    toast(String(err), true);
  }
});
$("ed-save").addEventListener("click", async () => {
  const path = await invoke("pick_save_file", { defaultName: "patterns.txt" });
  if (!path) return;
  try {
    await invoke("write_text_file", { path, contents: state.patternText });
    toast(t("toast.saved", { path }));
  } catch (err) {
    toast(String(err), true);
  }
});
$("ed-apply").addEventListener("click", async () => {
  if (monacoEditor) state.patternText = monacoEditor.getValue();
  await reparse();
  renderPatterns();
  toast(t("toast.appliedN", { n: state.patterns.length }));
});

(function initLang() {
  const sel = $("lang-select");
  sel.innerHTML = LANGS.map((l) => `<option value="${l.code}">${esc(l.label)}</option>`).join("");
  sel.value = LANG;
  sel.addEventListener("change", () => setLang(sel.value));
})();

const histState = { groups: [], pinA: null, pinB: null, selected: null, tabs: [], activeTab: null, tabSeq: 0 };

function fmtDate(unix) {
  return new Date(unix * 1000).toLocaleString();
}
function scanInfo(id) {
  for (const g of histState.groups) for (const s of g.scans) if (s.id === id) return { scan: s, group: g };
  return null;
}
function verLabel(g) {
  if (!g) return "?";
  return g.build_version ? `v${g.build_version}` : g.build_hash.slice(0, 8);
}
function pinLabel(id) {
  const info = scanInfo(id);
  return info ? `${esc(verLabel(info.group))} · ${esc(fmtDate(info.scan.created_at))}` : "";
}
function renderHistPins() {
  const el = $("hist-pins");
  if (!histState.pinA && !histState.pinB) {
    el.innerHTML = `<span class="pins-hint">${t("hist.pinHint")}</span>`;
  } else {
    const base = histState.pinA ? pinLabel(histState.pinA) : `<span class="pins-empty">${t("hist.unset")}</span>`;
    const target = histState.pinB ? pinLabel(histState.pinB) : `<span class="pins-empty">${t("hist.unset")}</span>`;
    el.innerHTML = `<span class="pins-slot"><span class="pins-tag">${t("hist.base")}</span>${base}</span><span class="pins-arrow">→</span><span class="pins-slot"><span class="pins-tag">${t("hist.target")}</span>${target}</span>`;
  }
  $("hist-compare").disabled = !(histState.pinA && histState.pinB);
}
function renderHistory() {
  const list = $("hist-list");
  if (!histState.groups.length) {
    list.innerHTML = `<div class="empty-pad">${t("hist.empty")}</div>`;
    renderHistPins();
    return;
  }
  list.innerHTML = histState.groups
    .map((g) => {
      const ver = g.build_version ? `v${esc(g.build_version)}` : t("hist.unknownVer");
      const scans = g.scans
        .map(
          (s) =>
            `<div class="hist-scan${s.id === histState.selected ? " active" : ""}" data-id="${s.id}"><div class="hist-scan-main"><span class="hist-scan-time d-addr">${esc(fmtDate(s.created_at))}</span><span class="hist-scan-meta">${esc(s.arch)} · ${t("hist.found")} ${s.found}/${s.total_matches}</span></div><div class="hist-scan-actions"><button class="pin${histState.pinA === s.id ? " pinned" : ""}" data-pin="a" data-id="${s.id}" title="${t("hist.setBase")}">${t("hist.base")}</button><button class="pin${histState.pinB === s.id ? " pinned" : ""}" data-pin="b" data-id="${s.id}" title="${t("hist.setTarget")}">${t("hist.target")}</button><button class="hist-del" data-del="${s.id}" title="${t("hist.delete")}">✕</button></div></div>`,
        )
        .join("");
      return `<div class="hist-group"><div class="hist-group-head" style="--vh:${hueOf(g.build_hash)}"><span class="hist-ver d-name">${ver}</span><span class="hist-hash d-addr">${esc(g.build_hash)}</span><span class="hist-count">${g.scans.length}</span></div>${scans}</div>`;
    })
    .join("");
  list.querySelectorAll(".hist-scan-main").forEach((el) =>
    el.addEventListener("click", () => selectHistScan(Number(el.parentElement.dataset.id))),
  );
  list.querySelectorAll("[data-pin]").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      if (b.dataset.pin === "a") histState.pinA = Number(b.dataset.id);
      else histState.pinB = Number(b.dataset.id);
      renderHistory();
    }),
  );
  list.querySelectorAll("[data-del]").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteHistScan(Number(b.dataset.del));
    }),
  );
  renderHistPins();
}
async function loadHistory() {
  try {
    histState.groups = await invoke("history_builds");
    renderHistory();
    renderTabs();
  } catch (e) {
    toast(String(e), true);
  }
}
function wireDetailSearch() {
  const inp = $("hist-search");
  if (!inp) return;
  const tbody = $("hist-tab-content").querySelector("tbody");
  if (!tbody) return;
  inp.addEventListener("input", () => {
    const term = inp.value.trim().toLowerCase();
    tbody.querySelectorAll("tr").forEach((tr) => {
      tr.style.display = !term || tr.textContent.toLowerCase().includes(term) ? "" : "none";
    });
  });
}

function activateTab(id) {
  histState.activeTab = id;
  const tab = histState.tabs.find((tb) => tb.id === id);
  histState.selected = tab && tab.type === "scan" ? tab.scanId : null;
  renderHistory();
  renderTabs();
  renderActiveTab();
}
function openTab(spec) {
  let tab = histState.tabs.find((tb) => tb.key === spec.key);
  if (!tab) {
    tab = { id: ++histState.tabSeq, ...spec };
    histState.tabs.push(tab);
  }
  activateTab(tab.id);
}
function closeTab(id) {
  const i = histState.tabs.findIndex((tb) => tb.id === id);
  if (i < 0) return;
  histState.tabs.splice(i, 1);
  if (histState.activeTab === id) {
    const next = histState.tabs[i] || histState.tabs[i - 1] || null;
    activateTab(next ? next.id : null);
  } else {
    renderTabs();
  }
}
function startRename(el, id) {
  el.contentEditable = "true";
  el.focus();
  el.addEventListener(
    "blur",
    () => {
      el.contentEditable = "false";
      const tab = histState.tabs.find((tb) => tb.id === id);
      if (tab) tab.title = el.textContent.trim() || tab.title;
      renderTabs();
    },
    { once: true },
  );
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      el.blur();
    }
  });
}
function renderTabs() {
  const bar = $("hist-tabs");
  bar.hidden = histState.tabs.length === 0;
  bar.innerHTML = histState.tabs
    .map(
      (tb) =>
        `<div class="hist-tab${tb.id === histState.activeTab ? " active" : ""}" data-tab="${tb.id}"><span class="hist-tab-title" data-tab="${tb.id}" title="${t("hist.rename")}">${esc(tb.title)}</span><button class="hist-tab-close" data-close="${tb.id}">✕</button></div>`,
    )
    .join("");
  bar.querySelectorAll(".hist-tab-title").forEach((el) => {
    el.addEventListener("click", () => activateTab(Number(el.dataset.tab)));
    el.addEventListener("dblclick", () => startRename(el, Number(el.dataset.tab)));
  });
  bar.querySelectorAll(".hist-tab-close").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      closeTab(Number(b.dataset.close));
    }),
  );
}
async function asmFor(hex, bits, base) {
  if (!hex) return `<div class="sym-empty">${t("hist.noBytes")}</div>`;
  const lines = await invoke("disassemble", { hex, bits, base: base || "0" });
  const hexFmt = hex.replace(/(..)/g, "$1 ").trim();
  const asm = lines.length ? lines.map((l) => esc(l)).join("\n") : esc(hexFmt);
  return `<div class="sym-hex mono">${esc(hexFmt)}</div><pre class="sym-asm">${asm}</pre>`;
}
async function toggleSymDetail(tr) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("sym-detail")) {
    next.remove();
    return;
  }
  tr.closest("tbody")
    .querySelectorAll(".sym-detail")
    .forEach((e) => e.remove());
  const bits = Number(tr.dataset.bits) || 64;
  const det = document.createElement("tr");
  det.className = "sym-detail";
  det.innerHTML = `<td colspan="${tr.children.length}"><div class="sym-body">${t("hist.loading")}</div></td>`;
  tr.after(det);
  const body = det.querySelector(".sym-body");
  try {
    if (tr.dataset.kind === "diff") {
      const oldAsm = await asmFor(tr.dataset.oldBytes, bits, tr.dataset.old);
      const newAsm = await asmFor(tr.dataset.newBytes, bits, tr.dataset.new);
      body.innerHTML = `<div class="sym-cols"><div class="sym-col"><div class="sym-h">${t("diff.colOld")} <span class="mono">${esc(tr.dataset.old || "-")}</span></div>${oldAsm}</div><div class="sym-col"><div class="sym-h">${t("diff.colNew")} <span class="mono">${esc(tr.dataset.new || "-")}</span></div>${newAsm}</div></div>`;
    } else {
      const diag = diagnosticsHtml(tr.dataset);
      body.innerHTML = diag + (await asmFor(tr.dataset.bytes, bits, tr.dataset.addr));
    }
  } catch (e) {
    body.textContent = String(e);
  }
}
async function renderActiveTab() {
  const c = $("hist-tab-content");
  const tab = histState.tabs.find((tb) => tb.id === histState.activeTab);
  if (!tab) {
    c.innerHTML = `<div class="insp-hint">${t("hist.selectHint")}</div>`;
    return;
  }
  try {
    if (tab.type === "scan") c.innerHTML = await scanTabHtml(tab);
    else if (tab.type === "diff") c.innerHTML = await diffTabHtml(tab);
    else if (tab.type === "difffiles") c.innerHTML = await diffFilesTabHtml(tab);
    else if (tab.type === "matrix") c.innerHTML = await matrixTabHtml(tab);
    const exp = $("hist-exp");
    if (exp && tab.type === "scan") exp.addEventListener("click", () => exportHistScan(tab.scanId));
    wireDetailSearch();
  } catch (e) {
    toast(String(e), true);
  }
}
function confChip(c) {
  if (c == null || c === "") return "";
  const n = Number(c);
  const cls = n >= 80 ? "hi" : n >= 40 ? "mid" : "lo";
  return ` <span class="conf-chip ${cls}" title="${t("diag.confidence")}">${n}</span>`;
}
function diagnosticsHtml(ds) {
  const parts = [];
  if (ds.confidence != null && ds.confidence !== "") {
    const c = Number(ds.confidence);
    parts.push(
      `<div class="diag-row"><span class="diag-k">${t("diag.confidence")}</span><span class="diag-bar"><span style="width:${c}%"></span></span><span class="diag-v">${c}/100</span></div>`,
    );
  }
  if (ds.trace)
    parts.push(`<div class="diag-row"><span class="diag-k">${t("diag.trace")}</span><span class="diag-v mono">${esc(ds.trace)}</span></div>`);
  if (ds.candidates)
    parts.push(
      `<div class="diag-row"><span class="diag-k">${t("diag.candidates")}</span><span class="diag-v mono">${esc(ds.candidates.split(",").join("   "))}</span></div>`,
    );
  return parts.length ? `<div class="sym-diag">${parts.join("")}</div>` : "";
}
async function scanTabHtml(tab) {
  const findings = await invoke("history_findings", { id: tab.scanId });
  if (!findings.length) return `<div class="insp-hint">${t("hist.noFindings")}</div>`;
  const info = scanInfo(tab.scanId);
  const g = info && info.group;
  const bits = info && info.scan.arch === "x86" ? 32 : 64;
  const ver = g && g.build_version ? `v${esc(g.build_version)}` : t("hist.unknownVer");
  const hue = g ? hueOf(g.build_hash) : 210;
  const rows = findings
    .map(
      (f) =>
        `<tr class="sym-row" data-kind="scan" data-bits="${bits}" data-addr="${esc(f.value || "")}" data-bytes="${esc(f.bytes || "")}" data-trace="${esc(f.trace || "")}" data-candidates="${esc(f.candidates || "")}" data-confidence="${f.confidence ?? ""}"><td class="d-name">${esc(f.name)}</td><td class="mono d-addr">${f.value ? esc(f.value) : "-"}</td><td>${catChip(f.category)}</td><td>${statusBadge(f.status)}${confChip(f.confidence)}</td></tr>`,
    )
    .join("");
  return `<div class="hist-banner" style="--vh:${hue}"><span class="hist-banner-ver">${ver}</span><span class="hist-banner-hash">${g ? esc(g.build_hash) : ""}</span><input id="hist-search" class="hist-search" type="text" placeholder="${t("hist.search")}" spellcheck="false" /><button id="hist-exp" class="btn btn-soft">${t("out.copy")}</button></div><div class="table-scroll"><table class="grid-table"><thead><tr><th>${t("col.name")}</th><th>${t("col.address")}</th><th>${t("col.category")}</th><th>${t("col.status")}</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
async function diffTabHtml(tab) {
  const view = await invoke("history_diff", { a: tab.a, b: tab.b });
  const info = scanInfo(tab.a);
  const bits = info && info.scan.arch === "x86" ? 32 : 64;
  return diffViewHtml(view, bits);
}
async function diffFilesTabHtml(tab) {
  const view = await invoke("diff_dumps", { old: tab.old, new: tab.new });
  return diffViewHtml(view, 64);
}
function diffViewHtml(view, bits) {
  const label = { moved: t("diff.moved"), new: t("diff.new"), removed: t("diff.removed") };
  const cls = { moved: "moved", new: "new", removed: "removed" };
  const tail = view.changed === true ? ` (${t("diff.changed")})` : view.changed === false ? ` (${t("diff.same")})` : "";
  const head = `${view.old_build || "?"} → ${view.new_build || "?"}${tail}`;
  const summary = `${t("diff.unchanged")} ${view.unchanged} · ${t("diff.new")} ${view.added} · ${t("diff.moved")} ${view.moved} · ${t("diff.removed")} ${view.removed}`;
  const rows = view.rows.length
    ? view.rows
        .map(
          (r) =>
            `<tr class="sym-row" data-kind="diff" data-bits="${bits}" data-old="${esc(r.old || "")}" data-new="${esc(r.new || "")}" data-old-bytes="${esc(r.old_bytes || "")}" data-new-bytes="${esc(r.new_bytes || "")}"><td class="d-name">${esc(r.name)}</td><td><span class="diff-tag ${cls[r.state]}">${label[r.state]}</span></td><td class="mono d-addr">${esc(r.old || "-")}</td><td class="mono d-addr">${esc(r.new || "-")}</td><td class="d-cat">${esc(r.category)}</td></tr>`,
        )
        .join("")
    : `<tr class="empty"><td colspan="5">${t("diff.noChanges")}</td></tr>`;
  return `<div class="diff-builds">${esc(head)}</div><div class="diff-summary">${summary}</div><div class="hist-toolbar"><input id="hist-search" class="hist-search" type="text" placeholder="${t("hist.search")}" spellcheck="false" /></div><div class="table-scroll"><table class="grid-table"><thead><tr><th>${t("col.name")}</th><th>${t("diff.colChange")}</th><th>${t("diff.colOld")}</th><th>${t("diff.colNew")}</th><th>${t("col.category")}</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
async function matrixTabHtml(tab) {
  const view = await invoke("history_matrix", { ids: tab.ids });
  const cols = view.columns.map((c) => `<th class="mx-col">${esc(c.label)}</th>`).join("");
  const rows = view.rows
    .map((r) => {
      let prev = null;
      const cells = r.cells
        .map((v) => {
          const changed = v != null && prev != null && v !== prev;
          if (v != null) prev = v;
          return `<td class="mono d-addr${changed ? " mx-changed" : ""}">${v ? esc(v) : "-"}</td>`;
        })
        .join("");
      return `<tr><td class="d-name mx-name">${esc(r.name)}</td><td>${catChip(r.category)}</td>${cells}</tr>`;
    })
    .join("");
  return `<div class="hist-toolbar"><input id="hist-search" class="hist-search" type="text" placeholder="${t("hist.search")}" spellcheck="false" /></div><div class="table-scroll mx-scroll"><table class="grid-table mx-table"><thead><tr><th class="mx-name">${t("col.name")}</th><th>${t("col.category")}</th>${cols}</tr></thead><tbody>${rows}</tbody></table></div>`;
}
function selectHistScan(id) {
  const info = scanInfo(id);
  openTab({ type: "scan", key: "s" + id, scanId: id, title: info ? verLabel(info.group) : `#${id}` });
}
async function exportHistScan(id) {
  try {
    const text = await invoke("history_export", { id, format: "txt" });
    await navigator.clipboard.writeText(text);
    toast(t("toast.copied"));
  } catch (e) {
    toast(String(e), true);
  }
}
async function deleteHistScan(id) {
  try {
    await invoke("history_delete", { id });
    if (histState.pinA === id) histState.pinA = null;
    if (histState.pinB === id) histState.pinB = null;
    histState.tabs = histState.tabs.filter((tb) => !(tb.type === "scan" && tb.scanId === id));
    if (!histState.tabs.some((tb) => tb.id === histState.activeTab)) {
      histState.activeTab = histState.tabs.length ? histState.tabs[histState.tabs.length - 1].id : null;
    }
    await loadHistory();
    renderActiveTab();
  } catch (e) {
    toast(String(e), true);
  }
}
async function clearHistory() {
  try {
    await invoke("history_clear");
    histState.pinA = null;
    histState.pinB = null;
    histState.tabs = [];
    histState.activeTab = null;
    histState.selected = null;
    await loadHistory();
    renderActiveTab();
  } catch (e) {
    toast(String(e), true);
  }
}
function compareHist() {
  if (!histState.pinA || !histState.pinB) return;
  const a = histState.pinA;
  const b = histState.pinB;
  const ga = (scanInfo(a) || {}).group;
  const gb = (scanInfo(b) || {}).group;
  openTab({ type: "diff", key: `d${a}-${b}`, a, b, title: `${verLabel(ga)} → ${verLabel(gb)}` });
}
function openMatrix() {
  const picks = histState.groups
    .filter((g) => g.scans.length)
    .map((g) => ({ id: g.scans[0].id, at: g.scans[0].created_at }));
  if (picks.length < 2) {
    toast(t("hist.needTwo"), true);
    return;
  }
  picks.sort((x, y) => x.at - y.at);
  const ids = picks.map((p) => p.id);
  openTab({ type: "matrix", key: "m" + ids.join(","), ids, title: t("hist.matrixTitle", { n: ids.length }) });
}
$("hist-refresh").addEventListener("click", loadHistory);
$("hist-compare").addEventListener("click", compareHist);
$("hist-matrix").addEventListener("click", openMatrix);
$("hist-difffiles").addEventListener("click", () => $("diff-file-input").click());
$("diff-file-input").addEventListener("change", async (e) => {
  const files = Array.from(e.target.files || []);
  e.target.value = "";
  if (files.length < 2) {
    toast(t("hist.diffPickTwo"), true);
    return;
  }
  try {
    const [a, b] = files;
    const [oldText, newText] = await Promise.all([a.text(), b.text()]);
    openTab({
      type: "difffiles",
      key: `df:${a.name}|${b.name}`,
      title: `${a.name} ↔ ${b.name}`,
      old: oldText,
      new: newText,
    });
  } catch (err) {
    toast(String(err), true);
  }
});
$("hist-clear").addEventListener("click", clearHistory);
$("hist-tab-content").addEventListener("click", (e) => {
  const tr = e.target.closest && e.target.closest("tr.sym-row");
  if (tr) toggleSymDetail(tr);
});

function relocalize() {
  $("mask-toggle").title = t(masked ? "mask.on" : "mask.off");
  $("t-arch-label").textContent = state.arch === "x64" ? t("ws.arch64") : t("ws.arch32");
  $("target-label").textContent = state.byClass ? t("ws.windowClass") : t("ws.targetProcess");
  $("w-target").placeholder = state.byClass ? t("ws.windowClassPh") : "MapleStory.exe";
  $("engine-badge").textContent = state.engineVer ? `${t("engine.label")} ${state.engineVer}` : t("engine.offline");
  const av = $("about-version");
  if (av) av.textContent = state.engineVer || "";
  $("w-source").value = state.sourceFile || t("ws.builtinSamples");
  setConn(state.connKey, state.connCls);
  setFoot(state.foot.titleKey, state.foot.subKey, state.foot.params, state.foot.rawSub);
  $("output-label").textContent = state.output ? t("out.label", { name: t(state.output.typeKey), n: state.output.n }) : t("out.nothing");
  if (!state.outputGenerated) $("output-text").textContent = t("out.default");
  buildTabs();
  renderResults();
  renderPatterns();
  asmSyncTarget();
  if (asmState.report) renderAsmResults(asmState.report);
  renderSigFiles();
  if (sigState.response) renderSigResults();
  if (histState.groups.length) {
    renderHistory();
    renderTabs();
    renderActiveTab();
  }
  if (state.selected) selectRow(state.selected);
  else {
    $("insp-name").textContent = t("insp.noSelection");
    $("insp-desc").textContent = t("insp.selectRow");
  }
  const sel = $("lang-select");
  if (sel) sel.value = LANG;
}
onLangChange = relocalize;

(async function boot() {
  injectIcons();
  $("t-arch-label").textContent = t("ws.arch64");
  $("target-label").textContent = t("ws.targetProcess");
  $("w-source").value = t("ws.builtinSamples");
  $("output-label").textContent = t("out.nothing");
  $("output-text").textContent = t("out.default");
  $("insp-name").textContent = t("insp.noSelection");
  $("insp-desc").textContent = t("insp.selectRow");
  $("mask-toggle").title = t("mask.off");
  setConn("idle", "");
  setFoot("foot.idle", "foot.idleSub");
  try {
    state.engineVer = await invoke("engine_version");
    $("engine-badge").textContent = `${t("engine.label")} ${state.engineVer}`;
  } catch {
    $("engine-badge").textContent = t("engine.offline");
  }
  const av = $("about-version");
  if (av) av.textContent = state.engineVer || "";
  const repo = $("about-repo");
  if (repo) repo.addEventListener("click", () => copyText(repo.textContent.trim()));
  await reparse();
  renderResults();
  renderPatterns();
})();
