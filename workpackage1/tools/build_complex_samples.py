"""Curated multi-file workflow cases; exact source spans, not padded examples."""
from pathlib import Path
import csv
import hashlib
import json
import re

from build_samples import ROOT, PINS, URLS, source, write, table, merge_manual_rows

SHARED = "dvwa/includes/dvwaPage.inc.php"


def unit(code_id, path, role, functions=None, guard_only=False):
    return dict(code_id=code_id, path=path, role=role, functions=functions, guard_only=guard_only)


CASES = [
    {
        "id": "SQLI-005", "project": "sqli-labs", "scope": "SQL注入", "title": "用户注册、登录与修改密码",
        "purpose": "追踪用户输入经历持久化、数据库读取、会话赋值和后续查询使用的关系；避免只检查单次请求。",
        "parameters": "注册POST submit/username/password/re_password；登录POST login_user/login_password；改密POST submit/current_password/password/re_password；Cookie Auth；SESSION username",
        "conditions": "三个独立HTTP阶段共享同一数据库与登录会话；审计全部步骤，不假定数据库或会话中的值自动可信。",
        "limitations": "依赖旧mysql_*接口、数据库users表及本地配置；不得部署审计片段替代完整靶场；Location/refresh调用前已有输出，运行行为受PHP输出缓冲影响。",
        "units": [unit("A", "Less-24/login_create.php", "注册写入"), unit("B", "Less-24/login.php", "登录读取与会话赋值"), unit("C", "Less-24/pass_change.php", "修改密码及退出"), unit("D", "sql-connections/sql-connect.php", "共享数据库连接")],
        "packets": [("P1", ["A", "D"]), ("P2", ["B", "C", "D"])],
        "dependencies": ["A写入users.username/password", "B查询users后把数据库返回的username写入SESSION", "C读取SESSION.username并生成UPDATE", "D提供A/B/C的数据库连接"],
        "assertions": {"A": ["mysql_escape_string", "insert into users"], "B": ["function sqllogin", '$_SESSION["username"] = $login'], "C": ['$_SESSION["username"]', "UPDATE users", "mysql_real_escape_string", "mysql_affected_rows"], "D": ["mysql_connect", "mysql_select_db"]},
        "review": "注册转义、数据库写入、登录数据库返回值、会话来源、改密查询及重定向完整保留；三个阶段不能作为互不关联的独立样本统计。",
    },
    {
        "id": "XSS-005", "project": "DVWA", "scope": "XSS", "title": "留言写入与再次展示",
        "purpose": "检查写入时处理与读取时输出编码是否匹配；数据库转义和HTML编码必须分别判断。",
        "parameters": "POST btnSign/txtName/mtxMessage；后续页面GET读取历史留言；页面另含btnClear操作",
        "conditions": "A为当前选定写入片段，B其余写入版本未提供，不能将A套用到所有配置。数据库持久化留言，dvwaGuestbook读取并返回HTML，page.body传给渲染器；运行配置与实际包含文件需在验证时记录。",
        "limitations": "mysqli连接、DVWA会话和security配置尚未实测；清理留言操作会改变后续读取结果；不要把客户端maxlength当服务器校验。",
        "units": [unit("A", "vulnerabilities/xss_s/source/low.php", "留言写入"), unit("B", "vulnerabilities/xss_s/index.php", "请求入口、表单与输出组装"), unit("C", SHARED, "数据库读取与HTML拼接", ["dvwaGuestbook"]), unit("D", SHARED, "运行配置读取", ["dvwaSecurityLevelGet"])],
        "packets": [("P1", ["A", "B", "C", "D"])],
        "dependencies": ["B选择并包含A", "A向guestbook写入name/comment", "B调用C读取guestbook并拼接到page.body", "C根据D的实际配置决定输出编码", "外围dvwaHtmlEcho输出page.body，完整实现另存context/dvwaPage.inc.php"],
        "assertions": {"A": ["mysqli_real_escape_string", "INSERT INTO guestbook"], "B": ["dvwaGuestbook()", "dvwaHtmlEcho", "btnClear", "maxlength"], "C": ["SELECT name, comment", "htmlspecialchars", "$guestbook .=", "return $guestbook"], "D": ["$_COOKIE", "default_security_level"]},
        "review": "写入过滤、读取SELECT、实际HTML输出、配置相关编码分支及外围调用全部关联；不以数据库转义推断HTML输出安全。",
    },
    {
        "id": "AUTH-001", "project": "DVWA", "scope": "权限越权", "title": "用户管理页面与数据接口",
        "purpose": "检查菜单可见性、页面访问、读取接口和修改接口是否分别执行同一业务权限规则。",
        "parameters": "页面GET；列表接口GET；更新接口POST JSON{id,first_name,surname}；会话用户；security配置",
        "conditions": "业务约定：仅admin可读取或修改所有用户资料。页面被包含的角色检查与security配置相关：low版本无额外执行语句；medium/high/impossible版本有角色检查。源码中的等级分支是实际控制条件，不作为最终标签。",
        "limitations": "普通用户与admin、匿名及不同security配置需要分别验证；页面授权不能替代独立接口授权；SQL拼接和DOM输出问题可另记录，本样本主要评估权限一致性。",
        "units": [unit("A", "vulnerabilities/authbypass/index.php", "管理页面入口"), unit("B", "vulnerabilities/authbypass/authbypass.js", "浏览器请求与显示"), unit("C", "vulnerabilities/authbypass/source/high.php", "被包含的页面角色检查", guard_only=True), unit("D", "vulnerabilities/authbypass/get_user_data.php", "读取所有用户资料接口"), unit("E", "vulnerabilities/authbypass/change_user_details.php", "修改指定用户资料接口"), unit("F", SHARED, "会话、身份与配置函数", ["dvwaSessionGrab", "dvwaPageStartup", "dvwaIsLoggedIn", "dvwaCurrentUser", "dvwaSecurityLevelGet"]), unit("G", SHARED, "完整菜单与页面渲染函数", ["dvwaHtmlEcho"])],
        "packets": [("P1", ["A", "B", "C", "F"]), ("P2", ["D", "E", "F"]), ("P3", ["G", "F"])],
        "dependencies": ["A启动会话并包含页面角色检查C", "A输出B，B调用D与E", "D/E是独立HTTP入口，不经过A的页面流程", "F定义实际身份与security读取", "G控制菜单可见性并输出A的page.body", "同一个AUTH-001跨P1/P2/P3综合判定，不能按片数当漏洞数"],
        "assertions": {"A": ["dvwaPageStartup", "require_once", "authbypass.js"], "B": ["change_user_details.php", "get_user_data.php", "JSON.stringify"], "C": ["dvwaCurrentUser", "http_response_code(403)", "exit"], "D": ["dvwaSecurityLevelGet", "dvwaCurrentUser", "SELECT user_id"], "E": ["REQUEST_METHOD", "php://input", "json_decode", "UPDATE users", "dvwaCurrentUser"], "F": ["function &dvwaSessionGrab", "function dvwaIsLoggedIn", "function dvwaCurrentUser", "function dvwaSecurityLevelGet"], "G": ["function dvwaHtmlEcho", 'dvwaCurrentUser() == "admin"', "authbypass", "$pPage[ 'body' ]"]},
        "review": "完整页面、客户端、两个独立接口、会话和菜单渲染均保存；high/impossible等真实权限分支保留。教学提示注释从C中排除，业务权限约定保留。",
    },
]


def function_spans(lines, names):
    spans = []
    for name in names:
        pat = re.compile(r"^function\s+&?" + re.escape(name) + r"\s*\(")
        start = next(i for i, line in enumerate(lines) if pat.search(line))
        # These inspected top-level functions have a closing brace at column 0.
        end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
        spans.append((start + 1, end + 1))
    return sorted(spans)


def prepare(project, spec):
    raw = source(project, spec["path"])
    lines = raw.decode("utf-8").splitlines()
    if spec["functions"]:
        spans = function_spans(lines, spec["functions"])
    elif spec["guard_only"]:
        start = next(i for i, line in enumerate(lines) if line.startswith("if (dvwaCurrentUser"))
        spans = [(start + 1, len(lines) - 1)]
    else:
        spans = [(1, len(lines))]
    selected = [(lines[n - 1], n) for start, end in spans for n in range(start, end + 1)]
    generated = bool(spec["functions"] or spec["guard_only"])
    code_lines = (["<?php"] if generated else []) + [line for line, _ in selected] + (["?>"] if generated else [])
    mapping = []
    if generated:
        mapping.append({"normalized_line": 1, "original_line": "", "operation": "wrapper"})
    for i, (_, n) in enumerate(selected, 1 + int(generated)):
        mapping.append({"normalized_line": i, "original_line": n, "operation": "retained"})
    if generated:
        mapping.append({"normalized_line": len(code_lines), "original_line": "", "operation": "wrapper"})
    return raw, "\n".join(code_lines) + "\n", spans, mapping


def build_complex_samples():
    rows, labels, reviews = [], [], []
    for case in CASES:
        sid, project = case["id"], case["project"]
        fragments = []
        for spec in case["units"]:
            raw, code, spans, mapping = prepare(project, spec)
            ext = ".js" if spec["path"].endswith(".js") else ".php"
            fragment_id = sid + "-" + spec["code_id"]
            raw_path = f"raw_samples/{sid}/{spec['code_id']}{ext}"
            normal_path = f"normalized_samples/{sid}/{spec['code_id']}{ext}"
            map_path = f"line_maps/{fragment_id}.csv"
            (ROOT / raw_path).parent.mkdir(parents=True, exist_ok=True)
            (ROOT / raw_path).write_bytes(raw)
            write(ROOT / normal_path, code)
            table(ROOT / map_path, mapping)
            fragments.append({"fragment_id": fragment_id, "code_id": spec["code_id"], "role": spec["role"], "source_file": spec["path"], "selected_spans": spans, "raw_file": raw_path, "normalized_file": normal_path, "line_map": map_path, "raw_sha256": hashlib.sha256(raw).hexdigest(), "normalized_sha256": hashlib.sha256(code.encode()).hexdigest(), "raw_lines": len(raw.decode().splitlines()), "normalized_lines": len(code.splitlines()), "required_tokens": case["assertions"][spec["code_id"]]})
        units_by_id = {f["code_id"]: f for f in fragments}
        packets = []
        for packet_id, codes in case["packets"]:
            # Packet limit counts all code lines, including shared dependencies.
            line_count = sum(units_by_id[c]["normalized_lines"] for c in codes)
            if line_count > 220:
                raise ValueError(f"{sid}-{packet_id}: {line_count} lines exceeds packet budget")
            sections = []
            for c in codes:
                f = units_by_id[c]
                code = (ROOT / f["normalized_file"]).read_text(encoding="utf-8")
                language = "javascript" if f["normalized_file"].endswith(".js") else "php"
                sections.append(f"关联片段 {f['fragment_id']}（{f['role']}），行号从其代码块第一行起计。\n```{language}\n{code.removesuffix(chr(10))}\n```\n")
            text = f"""样本ID：{sid}；输入包：{sid}-{packet_id}；版本：v2
业务场景：{case['title']}
来源引用：内部台账同ID；原始路径与提交号由人工追溯。
审计范围：{case['scope']}
参数与入口：{case['parameters']}
必要条件：{case['conditions']}
已知限制：{case['limitations']}
调用与依赖关系：
""" + "\n".join("- " + d for d in case["dependencies"]) + "\n\n" + "\n".join(sections) + f"\n期望输出：记录本包证据和未提供的依赖，不把缺失片段当不存在；使用片段ID及局部行号定位。收到该父样本全部输入包后，综合调用关系、存储与会话来源、权限条件形成结论。这里只提供代码输入，完整审计Prompt由组2设计。\n"
            input_path = f"llm_inputs/{sid}-{packet_id}.md"
            write(ROOT / input_path, text)
            packets.append({"packet_id": sid + "-" + packet_id, "fragment_ids": [sid + "-" + c for c in codes], "code_lines": line_count, "input_file": input_path})
        shared = sorted(set.intersection(*(set(codes) for _, codes in case["packets"]))) if len(case["packets"]) > 1 else []
        meta = {"sample_id": sid, "sample_kind": "multifile_workflow", "project": project, "source_url": URLS[project], "commit": PINS[project], "audit_scope": case["scope"], "language": "PHP+JavaScript" if sid.startswith("AUTH") else "PHP/HTML", "entry": case["title"], "parameters": case["parameters"], "conditions": case["conditions"], "limitations": case["limitations"], "dependencies": case["dependencies"], "fragments": fragments, "packets": packets, "shared_fragments": [sid + "-" + c for c in shared], "unique_code_lines": sum(f["normalized_lines"] for f in fragments), "max_packet_code_lines": max(p["code_lines"] for p in packets), "preprocess_version": "v2", "runtime_validation": "pending", "semantic_changes": "无；完整源码或完整函数逐行保留，仅生成函数包装行及统一换行"}
        meta_path = ROOT / "sample_metadata" / f"{sid}.json"
        if meta_path.exists():
            previous = json.loads(meta_path.read_text(encoding="utf-8"))
            for key in ("runtime_validation", "runtime_evidence", "validated_environment"):
                if key in previous:
                    meta[key] = previous[key]
        write(meta_path, json.dumps(meta, ensure_ascii=False, indent=2) + "\n")
        license_note = "GPL-3.0-or-later；见provenance" if project == "DVWA" else "课程指定教学来源；独立传播许可待核实"
        rows.append({"sample_id": sid, "project": project, "commit": PINS[project], "source_file": "多个文件；详见metadata.fragments", "source_url": URLS[project], "authorization": license_note, "language": meta["language"], "audit_scope": case["scope"], "parameters": case["parameters"], "source_start": "分片逐行映射", "source_end": "分片逐行映射", "normalized_lines": meta["unique_code_lines"], "normalized_file": f"normalized_samples/{sid}/", "metadata_file": f"sample_metadata/{sid}.json", "line_map": f"line_maps/{sid}-*.csv", "review_status": "见review_log.csv", "runtime_status": "未验证"})
        labels.append({"sample_id": sid, "ground_truth": "待验证", "evidence": "尚无POC结果", "runtime_status": "未验证"})
        reviews.append({"sample_id": sid, "review_date": "2026-10-12", "reviewer": "Codex静态复核v2", "entry_sink_checks": case["review"], "mapping_check": "每片逐行源文件映射和哈希，由verify_samples检查", "dependency_check": "；".join(case["dependencies"]), "finding": "静态关联路径完整；运行行为及最终标签待验证", "revision": "按完整处理器/函数分包，依赖重复提供；代码块不在字符串或条件内截断", "runtime_status": "未运行POC", "independent_human_review": "待组员复核"})
    merge_manual_rows(ROOT / "evaluation_private" / "labels.csv", labels)
    merge_manual_rows(ROOT / "review_log.csv", reviews)
    write(ROOT / "scenario_manifest.json", json.dumps([{"sample_id": c["id"], "title": c["title"], "purpose": c["purpose"], "metadata_file": f"sample_metadata/{c['id']}.json"} for c in CASES], ensure_ascii=False, indent=2) + "\n")
    return rows


if __name__ == "__main__":
    from build_samples import main
    main()
