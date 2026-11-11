"""IOC 强制聚类。纯同步逻辑。"""

import urllib.parse
from collections import defaultdict

from tools.safe_domain_whitelist import is_whitelisted
from tracing.ioc import extract_iocs, determine_anchor, _ioc_get


def group_mails_by_ioc(mails: list[dict], domain_intel: dict, ip_intel: dict) -> list[dict]:
    if not mails:
        return []

    ioc_mails = []
    no_ioc_mails = []
    for m in mails:
        iocs = extract_iocs(m, domain_intel, ip_intel)
        if iocs:
            ioc_mails.append((m, iocs))
        else:
            no_ioc_mails.append(m)

    n = len(ioc_mails)
    parent = list(range(n))

    def find(i):
        if parent[i] != i:
            parent[i] = find(parent[i])
        return parent[i]

    def union(i, j):
        root_i, root_j = find(i), find(j)
        if root_i != root_j:
            parent[root_i] = root_j

    ioc_to_idx = {}
    for idx, (_, iocs) in enumerate(ioc_mails):
        for ioc in iocs:
            ioc_to_idx.setdefault(ioc, []).append(idx)

    for indices in ioc_to_idx.values():
        for i in range(1, len(indices)):
            union(indices[0], indices[i])

    sender_to_idx = {}
    for idx, (m, _) in enumerate(ioc_mails):
        meta = m.get("meta", {})
        sender = (
            (meta.get("envelope_from") or "").lower().strip()
            or (meta.get("mail_from") or "").lower().strip()
        )
        if not sender:
            continue
        sender_to_idx.setdefault(sender, []).append(idx)

    for indices in sender_to_idx.values():
        if len(indices) < 2:
            continue
        for i in range(1, len(indices)):
            union(indices[0], indices[i])

    groups = {}
    for idx, (m, _) in enumerate(ioc_mails):
        root = find(idx)
        groups.setdefault(root, []).append(m)

    result: list[dict] = []
    sparse_campaigns: list[dict] = []

    for root, group_mails in groups.items():
        if not group_mails:
            continue

        first_res = group_mails[0].get("result", {})
        reason = first_res.get("summary", "判定为可疑/高危邮件")

        senders = set()
        subjects = set()
        attachment_names = set()
        from_names = set()
        domains = set()
        ips = set()

        for m in group_mails:
            meta = m.get("meta", {})
            res = m.get("result", {})
            props = res.get("ioc_details", {})

            senders.add(meta.get("envelope_from") or meta.get("mail_from", ""))
            subjects.add(meta.get("subject", ""))
            from_names.add(meta.get("sender_name", ""))
            for a in props.get("attachments", []) or []:
                fn = _ioc_get(a, "filename")
                if fn:
                    attachment_names.add(fn)

            for ioc in extract_iocs(m, domain_intel, ip_intel):
                if ioc.startswith("domain:"):
                    domains.add(ioc.replace("domain:", ""))
                if ioc.startswith("ip:"):
                    ips.add(ioc.replace("ip:", ""))

        camp_info = {
            "name": f"恶意域名 {list(domains)[0]}" if domains else (
                f"恶意IP {list(ips)[0]}" if ips else "恶意附件钓鱼"),
            "features": {
                "mailFrom": list(senders),
                "from": list(from_names),
                "subjects": list(subjects),
                "attachment_names": list(attachment_names),
                "domains": list(domains),
                "ips": list(ips),
            },
            "summary_reason": reason,
            "sample_count": len(group_mails),
        }

        anchor_field, confidence, anchor_values = determine_anchor(
            group_mails, domain_intel, ip_intel)
        camp_info["anchor_field"] = anchor_field
        camp_info["anchor_values"] = anchor_values
        camp_info["cluster_confidence"] = confidence

        if len(group_mails) == 1:
            sparse_campaigns.append(camp_info)
        else:
            result.append(camp_info)

    if sparse_campaigns:
        n_sparse = len(sparse_campaigns)
        sp_parent = list(range(n_sparse))

        def sp_find(i):
            if sp_parent[i] != i:
                sp_parent[i] = sp_find(sp_parent[i])
            return sp_parent[i]

        def sp_union(i, j):
            ri, rj = sp_find(i), sp_find(j)
            if ri != rj:
                sp_parent[ri] = rj

        from_to_idx = defaultdict(list)
        subj_to_idx = defaultdict(list)
        att_to_idx = defaultdict(list)

        for idx, sc in enumerate(sparse_campaigns):
            for fn in sc["features"].get("from") or []:
                fn = (fn or "").strip()
                if fn:
                    from_to_idx[fn].append(idx)
            for s in sc["features"].get("subjects") or []:
                s = (s or "").strip()
                if s:
                    subj_to_idx[s].append(idx)
            for a in sc["features"].get("attachment_names") or []:
                a = (a or "").strip()
                if a:
                    att_to_idx[a].append(idx)

        for indices in list(from_to_idx.values()) + list(subj_to_idx.values()) + list(att_to_idx.values()):
            for i in range(1, len(indices)):
                sp_union(indices[0], indices[i])

        merged_groups = defaultdict(list)
        for idx, sc in enumerate(sparse_campaigns):
            merged_groups[sp_find(idx)].append(sc)

        for group in merged_groups.values():
            if len(group) == 1:
                sc = group[0]
                sc["is_sparse"] = True
                f = sc["features"]
                if f.get("attachment_names"):
                    sc["anchor_field"] = "attachment_names"
                    sc["anchor_values"] = f["attachment_names"]
                    sc["cluster_confidence"] = "medium"
                elif len(f.get("mailFrom") or []) == 1:
                    sc["anchor_field"] = "mailFrom"
                    sc["anchor_values"] = f["mailFrom"]
                    sc["cluster_confidence"] = "medium"
                elif len(f.get("from") or []) == 1:
                    sc["anchor_field"] = "from"
                    sc["anchor_values"] = f["from"]
                    sc["cluster_confidence"] = "low"
                else:
                    sc["anchor_field"] = "none"
                    sc["anchor_values"] = []
                    sc["cluster_confidence"] = "low"
                result.append(sc)
            else:
                all_attach = set()
                all_from = set()
                all_subj = set()
                all_domains = set()
                all_ips = set()
                all_mailfrom = set()
                for sc in group:
                    all_attach.update(sc["features"].get("attachment_names") or [])
                    all_from.update(sc["features"].get("from") or [])
                    all_subj.update(sc["features"].get("subjects") or [])
                    all_domains.update(sc["features"].get("domains") or [])
                    all_ips.update(sc["features"].get("ips") or [])
                    all_mailfrom.update(sc["features"].get("mailFrom") or [])

                shared_atts = [a for a in all_attach if len(att_to_idx.get(a, [])) > 1]
                shared_froms = [f for f in all_from if len(from_to_idx.get(f, [])) > 1]
                shared_subjs = [s for s in all_subj if len(subj_to_idx.get(s, [])) > 1]

                if shared_atts:
                    anchor_field, anchor_values, confidence = "attachment_names", shared_atts, "medium"
                elif shared_froms:
                    anchor_field, anchor_values, confidence = "from", shared_froms, "medium"
                elif shared_subjs:
                    anchor_field, anchor_values, confidence = "subjects", shared_subjs, "low"
                else:
                    anchor_field, anchor_values, confidence = "none", [], "low"

                result.append({
                    "name": f"零星特征钓鱼（{len(group)}封，共享特征）",
                    "features": {
                        "mailFrom": list(all_mailfrom),
                        "from": list(all_from),
                        "subjects": list(all_subj)[:5],
                        "attachment_names": list(all_attach),
                        "domains": list(all_domains),
                        "ips": list(all_ips),
                    },
                    "summary_reason": f"零星合并活动（{len(group)}封，共享 from/subject/attachment 特征）",
                    "is_sparse": True,
                    "sample_count": len(group),
                    "anchor_field": anchor_field,
                    "anchor_values": anchor_values,
                    "cluster_confidence": confidence,
                })

    if no_ioc_mails:
        sender_groups: dict[str, list[dict]] = defaultdict(list)
        for m in no_ioc_mails:
            meta = m.get("meta", {})
            sender = (
                (meta.get("envelope_from") or meta.get("mail_from") or "").strip().lower()
            )
            sender_groups[sender or "_unknown"].append(m)

        for sender, group in sender_groups.items():
            group_attach = set()
            group_from = set()
            group_subj = set()
            for m in group:
                meta = m.get("meta", {})
                res = m.get("result", {})
                for a in res.get("ioc_details", {}).get("attachments", []) or []:
                    fn = _ioc_get(a, "filename")
                    if fn:
                        group_attach.add(fn)
                if meta.get("sender_name"):
                    group_from.add(meta.get("sender_name"))
                if meta.get("subject"):
                    group_subj.add(meta.get("subject"))

            real_sender = "" if sender == "_unknown" else sender
            reason = group[0].get("result", {}).get("summary", "无明确IOC特征")

            if real_sender:
                anchor_field = "mailFrom"
                anchor_values = [real_sender]
                confidence = "medium"
                name = f"无明确IOC的钓鱼（{real_sender}）"
            elif group_attach:
                anchor_field = "attachment_names"
                anchor_values = list(group_attach)[:3]
                confidence = "medium"
                name = "无明确IOC的钓鱼（附件特征）"
            elif group_from:
                anchor_field = "from"
                anchor_values = list(group_from)[:3]
                confidence = "low"
                name = "无明确IOC的钓鱼（显示名特征）"
            else:
                anchor_field = "none"
                anchor_values = []
                confidence = "low"
                name = "无明确IOC的钓鱼（无特征）"

            result.append({
                "name": name,
                "features": {
                    "mailFrom": [real_sender] if real_sender else [],
                    "from": list(group_from),
                    "subjects": list(group_subj)[:5],
                    "attachment_names": list(group_attach),
                    "domains": [],
                    "ips": [],
                },
                "summary_reason": reason,
                "sample_count": len(group),
                "anchor_field": anchor_field,
                "anchor_values": anchor_values,
                "cluster_confidence": confidence,
            })

    return result