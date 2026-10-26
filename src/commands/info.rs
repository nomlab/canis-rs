use std::fs;
use std::io;
use std::io::Write;
use anyhow::{bail, Result, anyhow};
use sha2::{Sha256, Digest as _};
use directories_next::ProjectDirs;
use serde_json;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::{Datelike, Duration, NaiveDate, NaiveDateTime, Local};
use webbrowser;

use crate::cli::InfoArgs;
use crate::config::Config;
use crate::db::{EventRepository, OperationRow, PathCount};

pub fn info(args: InfoArgs) -> Result<()>{
    // 設定ファイルを取得
    let config = if args.dbfile.is_some() {
        None
    } else if let Some(config_path) = &args.config {
        Some(Config::from_file(&config_path)?)
    } else {
        Some(Config::from_xdg()?)
    };

    let settings = config.as_ref().map(|c| &c.basic_settings);

    let default_db_path = || {
        ProjectDirs::from("", "", "canis")
            .unwrap()
            .data_dir()
            .join("canis.db")
            .display()
            .to_string()
    };

    let database_path = if let Some(path) = &args.dbfile {
        path.clone()
    } else if let Some(settings) = &settings {
        settings.dbfile.clone().unwrap_or_else(default_db_path)
    } else {
        default_db_path()
    };

    let db = EventRepository::new(&database_path)?;

    if !args.trace && !args.heatmap {
        info_default(&db, &args)?;
    }
    if args.trace {
        info_trace(&db, &args)?;
    }
    if args.heatmap {
        info_heatmap(&db, &args)?;
    }

    Ok(())
}

fn info_default(db: &EventRepository, args: &InfoArgs) -> Result<()>{

    // ファイルであることを確認
    let hash = if let Some(path) = &args.path {
        // ファイルであることを確認
        if !path.is_file() {
            return Err(anyhow!(
                "ファイルが存在しません: {:?}",
                path
            ));
        }

        let contents = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&contents);
        format!("{:x}", hasher.finalize())

    } else if let Some(hash) = &args.hash {
        validate_sha256_hash(hash)?;
        hash.clone()
    } else {
        return Err(anyhow!(
            "path または hash のどちらかを指定してください"
        ));
    };

    // DBから最古のレコードを検索
    let record = db.oldest_digest_by_hash(&hash)?;

    // 返り値から表示文を作成
    match record {
        Some(r) => {
            println!("検索結果:");
            println!("  存在した日時: {}", r.created_at);
            println!("  ファイルパス: {}", r.uri);
            println!("  ハッシュ値: {}", r.hash);
        }
        None => {
            println!("一致するハッシュのレコードは見つかりませんでした: {}", hash);
        }
    }

    Ok(())
}

fn info_trace(db: &EventRepository, args: &InfoArgs) -> Result<()>{
    // ファイルであることを確認
    let hash = if let Some(path) = &args.path {
        // ファイルであることを確認
        if !path.is_file() {
            return Err(anyhow!(
                "ファイルが存在しません: {:?}",
                path
            ));
        }

        let contents = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&contents);
        format!("{:x}", hasher.finalize())

    } else if let Some(hash) = &args.hash {
        validate_sha256_hash(hash)?;
        hash.clone()
    } else {
        return Err(anyhow!(
            "path または hash のどちらかを指定してください"
        ));
    };

    let records = db.get_operations_by_hash(&hash, args.since, args.until)?;

    if records.is_empty() {
        println!("No history found for hash: {}", hash);
        return Ok(());
    }

    // 3. 整形して出力
    for r in &records {
        println!("{}", format_line(r));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum Granularity {
    Monthly,
    Daily,
}

/// 1つの期間(月、または日)を表す
#[derive(Debug, Clone)]
pub struct Period {
    pub key: String,
    pub start: NaiveDateTime,
    pub end: NaiveDateTime,
}

pub fn info_heatmap(db: &EventRepository, args: &InfoArgs) -> Result<()> {
    let root_path = match (&args.path, &args.hash) {
        (Some(p), None) => {
            if !p.is_dir() { bail!("--heatmap requires a directory path, but a file was given"); }
            p.clone()
        }
        (None, Some(_)) => bail!("--heatmap does not support --hash; specify --path instead"),
        (None, None) => bail!("--path must be specified for --heatmap"),
        (Some(_), Some(_)) => unreachable!(),
    };
    let root_path_str = to_file_uri(&root_path)?;

    let (since, until) = match (args.since, args.until) {
        (Some(s), Some(u)) => (s, u),
        (s, u) => {
            let bounds = db.get_operation_time_bounds(&root_path_str)?;
            let (db_min, db_max) = bounds.ok_or_else(|| anyhow::anyhow!("No operations found under: {}", root_path_str))?;
            (s.unwrap_or(db_min), u.unwrap_or(db_max))
        }
    };

    let months = enumerate_months(since, until);
    let weeks = enumerate_weeks(since, until);
    let days = enumerate_days(since, until);
    let total_periods = months.len() + weeks.len() + days.len();

    if !confirm_large_period(total_periods, args.yes)? {
        println!("Aborted.");
        return Ok(());
    }

    let explanation = match &args.explain {
        Some(p) => load_explanations(p)?,
        None => None,
    };

    let mut trees: HashMap<String, DirNode> = HashMap::new();
    let mut build = |key: String, start: NaiveDateTime, end: NaiveDateTime, trees: &mut HashMap<String, DirNode>| -> Result<()> {
        let counts = db.get_operation_counts_by_prefix(&root_path_str, Some(start), Some(end))?;
        let mut tree = DirNode::build_tree(&root_path_str, counts);
        tree.augment_with_unvisited_dirs();
        tree.compute_total();
        if let Some(ref exp) = explanation {
            tree.apply_explanations(exp);
        }
        trees.insert(key, tree);
        Ok(())
    };

    for m in &months { build(format!("M:{}", m.key), m.start, m.end, &mut trees)?; }
    for w in &weeks   { build(format!("W:{}", w.key), w.start, w.end, &mut trees)?; }
    for d in &days    { build(format!("D:{}", d.key), d.start, d.end, &mut trees)?; }

    // 色基準(0を除く全期間・全ノードの最小/最大)
    let mut v_min = i64::MAX;
    let mut v_max = i64::MIN;
    for tree in trees.values() {
        collect_min_max(tree, &mut v_min, &mut v_max, true);
    }
    if v_min > v_max { v_min = 0; v_max = 1; } // データが皆無だった場合のフォールバック

    let html_content = generate_heatmap_html(&trees, &root_path_str)?;

    let proj_dirs = ProjectDirs::from("", "", "canis")
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve XDG configuration directory"))?;
    let dir = proj_dirs.data_dir().join("heatmaps");
    std::fs::create_dir_all(&dir)?;
    let filename = format!("heatmap_{}.html", Local::now().format("%Y%m%d_%H%M%S"));
    let output_path = dir.join(filename);
    std::fs::write(&output_path, html_content)?;

    println!("Heatmap generated: {}", output_path.display());
    let output_path_str = output_path.to_str().ok_or_else(|| anyhow::anyhow!("invalid UTF-8"))?;
    let file_url = format!("file://{}", output_path_str);
    if let Err(e) = webbrowser::open(&file_url) {
        eprintln!("Warning: failed to open browser automatically: {}", e);
    }
    Ok(())
}

fn confirm_large_period(total: usize, skip: bool) -> Result<bool> {
    const THRESHOLD: usize = 400; // 月+週+日を合算するため閾値を引き上げ
    if skip || total <= THRESHOLD { return Ok(true); }
    print!("This will generate {} heatmaps (months+weeks+days). This may take a while. Continue? [y/N]: ", total);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

fn to_file_uri(path: &std::path::Path) -> Result<String> {
    let absolute = path.canonicalize()?; // 相対パス対策としても正規化しておく
    Ok(format!("file://{}", absolute.display()))
}

fn validate_sha256_hash(hash: &str) -> anyhow::Result<()> {
    if hash.len() != 64 {
        return Err(anyhow!(
            "SHA-256ハッシュ値は64文字である必要があります。"
        ));
    }

    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "SHA-256ハッシュ値は16進数のみで構成されている必要があります。"
        ));
    }

    Ok(())
}

fn format_line(r: &OperationRow) -> String {
    let symbol = match r.operation.as_str() {
        "Create" => "C",
        "Move" => "M",
        "Modify" | "Append" | "Write" => "W",
        _ => "?",
    };

    match (r.operation.as_str(), &r.src_path) {
        ("Move", Some(src)) => {
            format!("{}  {}  {}  (from: {})", symbol, r.timestamp, r.uri, src)
        }
        _ => format!("{}  {}  {}", symbol, r.timestamp, r.uri),
    }
}

fn enumerate_months(since: NaiveDateTime, until: NaiveDateTime) -> Vec<Period> {
    let mut periods = Vec::new();
    let mut year = since.year();
    let mut month = since.month();

    loop {
        let (start, end) = month_range(year, month);
        if start > until {
            break;
        }
        periods.push(Period {
            key: format!("{:04}-{:02}", year, month),
            start,
            end,
        });

        if month == 12 {
            year += 1;
            month = 1;
        } else {
            month += 1;
        }

        if (year, month) > (until.year(), until.month()) {
            break;
        }
    }
    periods
}

fn month_range(year: i32, month: u32) -> (NaiveDateTime, NaiveDateTime) {
    let start = NaiveDate::from_ymd_opt(year, month, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();

    let (next_year, next_month) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
    let next_start = NaiveDate::from_ymd_opt(next_year, next_month, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    let end = next_start - Duration::seconds(1); // その月の最終秒

    (start, end)
}

fn enumerate_days(since: NaiveDateTime, until: NaiveDateTime) -> Vec<Period> {
    let mut periods = Vec::new();
    let mut current = since.date();
    let until_date = until.date();

    while current <= until_date {
        let start = current.and_hms_opt(0, 0, 0).unwrap();
        let end = current.and_hms_opt(23, 59, 59).unwrap();
        periods.push(Period {
            key: current.format("%Y-%m-%d").to_string(),
            start,
            end,
        });
        current += Duration::days(1);
    }
    periods
}

#[derive(Debug, Serialize)]
struct TreeWithBounds {
    tree: DirNode,
    v_min: i64,
    v_max: i64,
}

fn collect_min_max(node: &DirNode, v_min: &mut i64, v_max: &mut i64, is_root: bool) {
    if !is_root && node.total_count > 0 {
        if node.total_count < *v_min { *v_min = node.total_count; }
        if node.total_count > *v_max { *v_max = node.total_count; }
    }
    for child in node.children.values() {
        collect_min_max(child, v_min, v_max, false);
    }
}

fn generate_heatmap_html(
    trees: &HashMap<String, DirNode>,
    original_root_path: &str,
) -> Result<String> {
    // プレフィックスごとに v_min, v_max を計算する
    let mut bounds_by_granularity: HashMap<&str, (i64, i64)> = HashMap::new();
    for prefix in ["M:", "W:", "D:"] {
        let mut v_min = i64::MAX;
        let mut v_max = i64::MIN;
        for (key, tree) in trees {
            if key.starts_with(prefix) {
                collect_min_max(tree, &mut v_min, &mut v_max, true);
            }
        }
        if v_min > v_max {
            v_min = 0;
            v_max = 1;
        }
        bounds_by_granularity.insert(prefix, (v_min, v_max));
    }

    let mut wrapped: HashMap<String, TreeWithBounds> = HashMap::new();
    for (key, tree) in trees {
        let prefix = &key[..2]; // "M:", "W:", "D:" のいずれか
        let (v_min, v_max) = bounds_by_granularity.get(prefix).copied().unwrap_or((0, 1));
        wrapped.insert(key.clone(), TreeWithBounds { tree: tree.clone(), v_min, v_max });
    }

    let trees_json = serde_json::to_string(&wrapped)?;
    let html = HTML_TEMPLATE
        .replace("__TREES_JSON__", &trees_json)
        .replace("__ORIGINAL_ROOT_PATH__", original_root_path);
    Ok(html)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExplanationNode {
    pub path: String,
    pub description: String,
    #[serde(default)]
    pub children: HashMap<String, ExplanationNode>,
}

fn load_explanations(path: &std::path::Path) -> Result<Option<ExplanationNode>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    let root: ExplanationNode = serde_json::from_str(&content)?;
    Ok(Some(root))
}

#[derive(Debug, Clone)]
pub struct WeekPeriod {
    pub key: String,       // 週開始日 "2026-07-26" をキーにする
    pub start: NaiveDateTime,
    pub end: NaiveDateTime,
}

fn enumerate_weeks(since: NaiveDateTime, until: NaiveDateTime) -> Vec<WeekPeriod> {
    let mut weeks = Vec::new();
    // 日曜始まりで、sinceが含まれる週の日曜まで遡る
    let since_date = since.date();
    let days_from_sunday = since_date.weekday().num_days_from_sunday();
    let mut week_start = since_date - Duration::days(days_from_sunday as i64);

    while week_start <= until.date() {
        let week_end = week_start + Duration::days(6);
        let start_dt = week_start.and_hms_opt(0, 0, 0).unwrap();
        let end_dt = week_end.and_hms_opt(23, 59, 59).unwrap();
        weeks.push(WeekPeriod {
            key: week_start.format("%Y-%m-%d").to_string(),
            start: start_dt,
            end: end_dt,
        });
        week_start += Duration::days(7);
    }
    weeks
}

#[derive(Debug, Serialize,Clone)]
pub struct DirNode {
    pub name: String,
    pub full_path: String,
    pub own_count: i64,
    pub total_count: i64,
    pub children: HashMap<String, DirNode>,
    #[serde(skip)]
    pub from_db: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub is_file: bool,
}

impl DirNode {
    fn new(name: String, full_path: String, from_db: bool, is_file: bool) -> Self {
        Self {
            name,
            full_path,
            own_count: 0,
            total_count: 0,
            children: HashMap::new(),
            from_db,
            description: None, // 追加。既存の呼び出し箇所(build_tree, augment_with_unvisited_dirs)は変更不要
            is_file
        }
    }

    pub fn build_tree(root_path: &str, counts: Vec<PathCount>) -> DirNode {
        let normalized_root = root_path.trim_end_matches('/').to_string();
        let root_name = normalized_root.rsplit('/').next().unwrap_or(&normalized_root).to_string();
        let mut root = DirNode::new(root_name, normalized_root.clone(), true, false);

        for pc in counts {
            let rel = match pc.uri.strip_prefix(&format!("{}/", normalized_root)) {
                Some(r) => r,
                None => continue,
            };
            let parts: Vec<&str> = rel.split('/').collect();
            let mut current = &mut root;
            let mut current_path = normalized_root.clone();

            // ディレクトリ部分を辿る(ファイル名は除く)
            for part in &parts[..parts.len().saturating_sub(1)] {
                current_path = format!("{}/{}", current_path, part);
                current = current.children.entry(part.to_string())
                    .or_insert_with(|| DirNode::new(part.to_string(), current_path.clone(), true, false));
            }

            // 追加: ファイル自体もノードとして子に追加する
            if let Some(file_name) = parts.last() {
                let file_path = format!("{}/{}", current_path, file_name);
                let file_node = current.children.entry(format!("\0file:{}", file_name))
                    .or_insert_with(|| DirNode::new(file_name.to_string(), file_path, true, true));
                file_node.own_count += pc.count;
            }
        }

        root.compute_total();
        root
    }

    pub fn augment_with_unvisited_dirs(&mut self) {
        let fs_path = self.full_path.strip_prefix("file://").unwrap_or(&self.full_path);

        if let Ok(entries) = std::fs::read_dir(fs_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let child_name = entry.file_name().to_string_lossy().to_string();

                // DBの情報として既に存在するディレクトリなら何もしない(下でまとめて再帰する)
                if self.children.contains_key(&child_name) {
                    continue;
                }

                // DBに存在しなかった = 一度も操作されていないディレクトリ
                // own_count, total_count は 0 のまま、from_db: false の葉ノードとして追加するだけ
                let child_full_path = format!("{}/{}", self.full_path, child_name);
                self.children.insert(
                    child_name.clone(),
                    DirNode::new(child_name, child_full_path, false, false),
                );
                // ここでは絶対に再帰しない
            }
        }
        // read_dirが失敗した場合(権限エラー等)は、そのまま何もせず諦める

        // DBの情報から来ていたノード(from_db == true)についてのみ、再帰的に同じ処理を行う
        let db_derived_keys: Vec<String> = self
            .children
            .iter()
            .filter(|(_, c)| c.from_db)
            .map(|(k, _)| k.clone())
            .collect();

        for key in db_derived_keys {
            if let Some(child) = self.children.get_mut(&key) {
                child.augment_with_unvisited_dirs();
            }
        }
    }

    fn compute_total(&mut self) -> i64 {
        if self.is_file {
            self.total_count = self.own_count;
            return self.total_count;
        }
        let children_sum: i64 = self.children.values_mut().map(|c| c.compute_total()).sum();
        self.total_count = self.own_count + children_sum;
        self.total_count
    }

    pub fn apply_explanations(&mut self, explanation: &ExplanationNode) {
        self.description = Some(explanation.description.clone());
        for (key, child_explanation) in &explanation.children {
            if let Some(child_node) = self.children.get_mut(key) {
                child_node.apply_explanations(child_explanation);
            }
            // DirNode側に対応する子が無い場合は、その説明は無視する(黙って読み飛ばす)
        }
    }
}

const HTML_TEMPLATE: &str = r##"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body { font-family: sans-serif; margin: 16px; }
  #selector { margin-bottom: 12px; }
  .year-block { margin-bottom: 8px; }
  .year-label { font-weight: bold; margin-right: 8px; }
  .period-btn {
    display: inline-block; width: 48px; padding: 6px 0; margin: 2px;
    text-align: center; border-radius: 4px; cursor: pointer;
    background: #ddd; color: #333; font-size: 12px;
  }
  .period-btn.available { background: #4a90d9; color: white; }
  .period-btn.available.empty { background: #a9c6e8; color: #333; }
  .period-btn.selected { outline: 3px solid #222; }
  .period-btn.disabled { background: #eee; color: #bbb; cursor: not-allowed; }
  #month-select { margin-bottom: 8px; }
  text { font-family: sans-serif; font-size: 11px; pointer-events: none; }
  rect { stroke: #fff; stroke-width: 1; cursor: pointer; }
  rect.leaf { cursor: default; }
  .day-grid {
    display: grid;
    grid-template-columns: repeat(7, 48px);
    gap: 2px;
  }
  rect.file-node {
    stroke-dasharray: 3,2;
  }
  .weekday-row {
    display: grid;
    grid-template-columns: repeat(7, 48px);
    gap: 2px;
    margin-bottom: 4px;
  }
  .weekday-label {
    text-align: center;
    font-weight: bold;
    font-size: 12px;
  }
  .week-row {
    display: grid;
    grid-template-columns: 40px repeat(7, 48px);
    gap: 2px;
    margin-bottom: 2px;
    align-items: stretch;
  }
  .weekday-row-with-week {
    display: grid;
    grid-template-columns: 40px repeat(7, 48px);
    gap: 2px;
    margin-bottom: 4px;
  }
  .week-btn {
    background: #6b7280;
    color: white;
    width: 40px;
    box-sizing: border-box;
  }
  rect.root-node {
    stroke: black !important;
    stroke-width: 1px !important;
  }
  #main-area {
    display: flex;
    gap: 16px;
    align-items: flex-start;
    max-width: 1240px; /* SVG(900px) + gap(16px) + panel(320px) 程度に合わせる */
  }
  #description-panel {
    width: 320px; padding: 12px; font-size: 13px; color: #333;
    border-left: 1px solid #ddd; box-sizing: border-box;
  }
  text.node-label {
  font-size: 11px;
}
</style>
</head>
<body>

<div id="selector"></div>
<div id="main-area">
  <svg id="heatmap" xmlns="http://www.w3.org/2000/svg" width="900" height="650" viewBox="0 0 900 650">
    <g id="chart"></g>
  </svg>
  <div id="description-panel">
    期間とディレクトリを選択すると、ここに説明が表示されます。
  </div>
</div>
<script>
  const TREES = __TREES_JSON__;
  const GRANULARITY = "__GRANULARITY__"; // "monthly" or "daily"
//   const COLOR_BASIS = __COLOR_BASIS__;
  // const V_MIN = __V_MIN__;
  // const V_MAX = __V_MAX__;
  const ORIGINAL_ROOT_PATH = "__ORIGINAL_ROOT_PATH__"; // Rust側から埋め込む、最初に指定したディレクトリのuri
  const DISPLAY_DEPTH = 2;
  const ANCESTOR_WIDTH = 70;
  const COLUMN_WIDTH = 160;
  const CANVAS_HEIGHT = 650;

  // ---- ツリー探索・レイアウト部分 (既存ロジックをそのまま流用) ----
  function findNode(tree, path) {
    function search(node) {
      if (node.full_path === path) return node;
      for (const key in node.children) {
        const found = search(node.children[key]);
        if (found) return found;
      }
      return null;
    }
    return search(tree);
  }

  function findParent(tree, path) {
    function search(node) {
      for (const key in node.children) {
        const child = node.children[key];
        if (child.full_path === path) return node;
        const found = search(child);
        if (found) return found;
      }
      return null;
    }
    return search(tree);
  }

  function computeUnits(node, remainingDepth) {
    const keys = Object.keys(node.children);
    if (remainingDepth === 0 || keys.length === 0) return 1;
    let sum = 0;
    for (const key of keys) sum += computeUnits(node.children[key], remainingDepth - 1);
    return sum;
  }

  let currentTreeData = null;

  function colorFor(totalCount) {
    if (totalCount === 0) return "rgb(190,190,190)";
    const vMin = currentTreeData.v_min;
    const vMax = currentTreeData.v_max;
    const t = vMax > vMin ? (totalCount - vMin) / (vMax - vMin) : 1.0;
    const r1 = 37,  g1 = 99,  b1 = 235;
    const r2 = 220, g2 = 38,  b2 = 38;
    const r = Math.round(r1 + (r2 - r1) * t);
    const g = Math.round(g1 + (g2 - g1) * t);
    const b = Math.round(b1 + (b2 - b1) * t);
    return `rgb(${r},${g},${b})`;
  }

  function makeRect(node, x, y, w, h, hasChildren, clickable) {
    const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    rect.setAttribute("x", x); rect.setAttribute("y", y);
    rect.setAttribute("width", w); rect.setAttribute("height", h);

    if (node.full_path === ORIGINAL_ROOT_PATH) {
      rect.setAttribute("fill", "white");
      rect.classList.add("root-node");
    } else {
      rect.setAttribute("fill", colorFor(node.total_count));
    }
    if (node.is_file) {
      rect.classList.add("file-node"); // 点線枠など、CSSで区別
    } else if (!hasChildren) {
      rect.classList.add("leaf");
    }
    group.appendChild(rect);

    if (h > 14) {
      const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
      text.setAttribute("x", x + 4); text.setAttribute("y", y + 22);
      text.textContent = node.name + " (" + node.total_count + ")";
      text.classList.add("node-label");
      group.appendChild(text);
    }
    if (clickable) {
      group.addEventListener("click", () => renderTree(node.full_path));
    }
    return group;
  }

  let currentTree = null;

  function layoutColumn(node, x, y0, y1, remainingDepth, chart, isRootColumn) {
    const hasChildren = Object.keys(node.children).some(k => !node.children[k].is_file);
    const clickable = node.total_count > 0;
    chart.appendChild(makeRect(node, x, y0, COLUMN_WIDTH, y1 - y0, hasChildren, clickable));

    if (remainingDepth === 0 || Object.keys(node.children).length === 0) return;

    const dirEntries = Object.values(node.children)
      .filter(c => !c.is_file)
      .sort((a, b) => b.total_count - a.total_count);

    const shouldShowFiles = isRootColumn || remainingDepth === 1;
    let fileEntries = [];
    if (shouldShowFiles) {
      fileEntries = Object.values(node.children)
        .filter(c => c.is_file)
        .sort((a, b) => b.total_count - a.total_count)
        .slice(0, 10);
    }

    const allEntries = [...dirEntries, ...fileEntries];
    if (allEntries.length === 0) return;

    const totalUnits = allEntries.reduce((sum, c) => sum + (c.is_file ? 1 : computeUnits(c, remainingDepth - 1)), 0);

    let cursor = y0;
    const nextX = x + COLUMN_WIDTH;
    for (const entry of allEntries) {
      const units = entry.is_file ? 1 : computeUnits(entry, remainingDepth - 1);
      const h = (y1 - y0) * (units / totalUnits);
      if (entry.is_file) {
        chart.appendChild(makeRect(entry, nextX, cursor, COLUMN_WIDTH, h, false, entry.total_count > 0));
      } else {
        layoutColumn(entry, nextX, cursor, cursor + h, remainingDepth - 1, chart, false);
      }
      cursor += h;
    }
  }

  function renderTree(rootPath) {
    const chart = document.getElementById("chart");
    chart.innerHTML = "";
    const rootNode = findNode(currentTreeData.tree, rootPath); // .tree経由でアクセス
    const parentNode = findParent(currentTreeData.tree, rootPath);

    let startX = 0;
    if (parentNode) {
      chart.appendChild(makeRect(parentNode, 0, 0, ANCESTOR_WIDTH, CANVAS_HEIGHT, true, true));
      startX = ANCESTOR_WIDTH;
    }
    layoutColumn(rootNode, startX, 0, CANVAS_HEIGHT, DISPLAY_DEPTH, chart);
  }

  // ---- ここから期間選択UI ----

  function selectPeriod(key) {
    const data = TREES[key];
    if (!data) return;
    currentTreeData = data;
    renderTree(data.tree.full_path);

    // 全ての選択済みハイライトを解除してから、今回選ばれたボタンだけに付け直す
    document.querySelectorAll(".period-btn").forEach(b => b.classList.remove("selected"));
    const btn = document.querySelector(`[data-key="${key}"]`);
    if (btn) btn.classList.add("selected");
  }

  function buildMonthGrid(container, yearMonthKeys, onSelectMonth) {
    const years = [...new Set(yearMonthKeys.map(k => k.slice(0, 4)))].sort().reverse();
    container.innerHTML = "";

    for (const year of years) {
      const block = document.createElement("div");
      block.className = "year-block";
      const label = document.createElement("span");
      label.className = "year-label";
      label.textContent = year + "年";
      block.appendChild(label);

      for (let m = 1; m <= 12; m++) {
        const key = `${year}-${String(m).padStart(2, "0")}`;
        const btn = document.createElement("div");
        btn.className = "period-btn";
        btn.textContent = m + "月";
        btn.dataset.key = key;

        if (yearMonthKeys.includes(key)) {
          btn.classList.add("available");
          if (TREES["M:" + key] && TREES["M:" + key].tree.total_count === 0) {
            btn.classList.add("empty");
          }
          btn.dataset.key = "M:" + key;
          btn.addEventListener("click", () => onSelectMonth(key));
        } else {
          btn.classList.add("disabled");
        }
        block.appendChild(btn);
      }
      container.appendChild(block);
    }
  }

  function buildDayGrid(container, monthKey) {
    container.innerHTML = "";
    const [year, month] = monthKey.split("-").map(Number);
    const firstDay = new Date(year, month - 1, 1);
    const daysInMonth = new Date(year, month, 0).getDate();
    const startWeekday = firstDay.getDay(); // 0=日曜

    const weekdayRow = document.createElement("div");
    ["日","月","火","水","木","金","土"].forEach(w => {
      const span = document.createElement("span");
      span.style.display = "inline-block"; span.style.width = "48px"; span.style.textAlign = "center";
      span.textContent = w;
      weekdayRow.appendChild(span);
    });
    container.appendChild(weekdayRow);

    const grid = document.createElement("div");
    for (let i = 0; i < startWeekday; i++) {
      const filler = document.createElement("span");
      filler.style.display = "inline-block"; filler.style.width = "48px"; filler.style.height = "30px";
      grid.appendChild(filler);
    }
    for (let d = 1; d <= daysInMonth; d++) {
      const key = `${year}-${String(month).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      const btn = document.createElement("div");
      btn.className = "period-btn";
      btn.textContent = d;
      btn.dataset.key = key;
      if (TREES[key]) {
        btn.classList.add("available");
        if (TREES[key].total_count === 0) btn.classList.add("empty");
        btn.addEventListener("click", () => selectPeriod(key));
      } else {
        btn.classList.add("disabled");
      }
      grid.appendChild(btn);
    }
    container.appendChild(grid);
  }
  function buildDayGrid(container, monthKey) {
    container.innerHTML = "";
    const [year, month] = monthKey.split("-").map(Number);
    const firstDay = new Date(year, month - 1, 1);
    const daysInMonth = new Date(year, month, 0).getDate();
    const startWeekday = firstDay.getDay();

    const weekdayRow = document.createElement("div");
    weekdayRow.className = "weekday-row";
    ["日","月","火","水","木","金","土"].forEach(w => {
      const span = document.createElement("span");
      span.className = "weekday-label";
      span.textContent = w;
      weekdayRow.appendChild(span);
    });
    container.appendChild(weekdayRow);

    const grid = document.createElement("div");
    grid.className = "day-grid";
    for (let i = 0; i < startWeekday; i++) {
      const filler = document.createElement("span");
      grid.appendChild(filler); // 空セル(グリッドの位置調整用)
    }
    for (let d = 1; d <= daysInMonth; d++) {
      const key = `${year}-${String(month).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      const btn = document.createElement("div");
      btn.className = "period-btn";
      btn.textContent = d;
      btn.dataset.key = key;
      if (TREES[key]) {
        btn.classList.add("available");
        if (TREES[key].total_count === 0) btn.classList.add("empty");
        btn.addEventListener("click", () => selectPeriod(key));
      } else {
        btn.classList.add("disabled");
      }
      grid.appendChild(btn);
    }
    container.appendChild(grid);
  }

  function buildDayGridWithWeeks(container, monthKey) {
    container.innerHTML = "";
    const [year, month] = monthKey.split("-").map(Number);
    const firstDay = new Date(year, month - 1, 1);
    const daysInMonth = new Date(year, month, 0).getDate();
    const startWeekday = firstDay.getDay();

    const weekdayRow = document.createElement("div");
    weekdayRow.className = "weekday-row-with-week";
    const emptyLabel = document.createElement("span");
    weekdayRow.appendChild(emptyLabel);
    ["日","月","火","水","木","金","土"].forEach(w => {
      const span = document.createElement("span");
      span.className = "weekday-label";
      span.textContent = w;
      weekdayRow.appendChild(span);
    });
    container.appendChild(weekdayRow);

    let dayCounter = 1 - startWeekday;
    let weekIndex = 1;

    while (dayCounter <= daysInMonth) {
      const row = document.createElement("div");
      row.className = "week-row";
      const weekStartDate = new Date(year, month - 1, dayCounter);

      const weekKey = formatDateKey(weekStartDate);
      const weekBtn = document.createElement("div");
      weekBtn.className = "period-btn week-btn";
      weekBtn.textContent = "W" + weekIndex;
      if (TREES["W:" + weekKey]) {
        weekBtn.classList.add("available");
        if (TREES["W:" + weekKey].tree.total_count === 0) weekBtn.classList.add("empty");
        weekBtn.dataset.key = "W:" + weekKey;
        weekBtn.addEventListener("click", () => selectPeriod("W:" + weekKey));
      } else {
        weekBtn.classList.add("disabled");
      }
      row.appendChild(weekBtn);

      for (let i = 0; i < 7; i++) {
        const d = dayCounter + i;
        const cell = document.createElement("div");
        if (d < 1 || d > daysInMonth) {
          cell.className = "period-btn";
        } else {
          const dayKey = `${year}-${String(month).padStart(2,"0")}-${String(d).padStart(2,"0")}`;
          cell.className = "period-btn";
          cell.textContent = d;
          if (TREES["D:" + dayKey]) {
            cell.classList.add("available");
            if (TREES["D:" + dayKey].tree.total_count === 0) cell.classList.add("empty");
            cell.dataset.key = "D:" + dayKey;
            cell.addEventListener("click", () => selectPeriod("D:" + dayKey));
          } else {
            cell.classList.add("disabled");
          }
        }
        row.appendChild(cell);
      }

      container.appendChild(row);
      dayCounter += 7;
      weekIndex++;
    }
  }

  function formatDateKey(date) {
    return `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,"0")}-${String(date.getDate()).padStart(2,"0")}`;
  }

  function updateDescriptionPanel(node) {
    const panel = document.getElementById("description-panel");
    panel.textContent = node.description ? node.description : "(このディレクトリの説明はまだ登録されていません)";
  }

  function renderTree(rootPath) {
    const chart = document.getElementById("chart");
    chart.innerHTML = "";
    const rootNode = findNode(currentTreeData.tree, rootPath);
    const parentNode = findParent(currentTreeData.tree, rootPath);

    let startX = 0;
    if (parentNode) {
      chart.appendChild(makeRect(parentNode, 0, 0, ANCESTOR_WIDTH, CANVAS_HEIGHT, true, true));
      startX = ANCESTOR_WIDTH;
    }
    layoutColumn(rootNode, startX, 0, CANVAS_HEIGHT, DISPLAY_DEPTH, chart, true);
    updateDescriptionPanel(rootNode);
  }

  function init() {
    const selector = document.getElementById("selector");
    const monthSelector = document.createElement("div");
    const daySelector = document.createElement("div");
    selector.appendChild(monthSelector);
    selector.appendChild(daySelector);

    const monthKeys = Object.keys(TREES)
      .filter(k => k.startsWith("M:"))
      .map(k => k.slice(2));

    buildMonthGrid(monthSelector, monthKeys, (monthKey) => {
      selectPeriod("M:" + monthKey);
      buildDayGridWithWeeks(daySelector, monthKey);
    });
    // 初期状態ではカレンダーのみ表示、ヒートマップ未選択
  }

  init();
</script>
</body>
</html>"##;
