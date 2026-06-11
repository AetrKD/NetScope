// ═══════════════════════════════════════════════════════════
// NetScope AI - UI Handlers (Modals, Settings, Rules, etc.)
// ═══════════════════════════════════════════════════════════

// ── IP 별명 모달 ─────────────────────────────────────────
const aliasModal = $('aliasModal'), aliasListC = $('aliasListContainer'), aliasEmpty = $('aliasEmptyState');
function renderAliasList() {
    if (!aliasListC) return;
    aliasListC.innerHTML = '';
    const keys = Object.keys(ipAliases);
    if (!keys.length) { if(aliasEmpty) aliasListC.appendChild(aliasEmpty); return; }
    keys.forEach(ip => {
        const item = document.createElement('div'); item.className = 'rule-item';
        const data = ipAliases[ip] || {};
        const name = data.name || data; // backward compatibility
        const policy = data.policy || 'SAVE_ALL';
        const policyBadge = policy === 'SAVE_ALL' ? '<span class="badge badge-in">전부 저장</span>' : policy === 'DO_NOT_SAVE' ? '<span class="badge badge-out">저장 안함</span>' : '<span class="badge badge-tcp">자동 (AI)</span>';
        item.innerHTML = `<div class="rule-text"><span style="color:var(--accent-blue);font-weight:600;">${name}</span> (${ip}) ${policyBadge}</div><button onclick="removeAlias('${ip}')">삭제</button>`;
        aliasListC.appendChild(item);
    });
}


document.addEventListener('DOMContentLoaded', () => {
    const cancelBtn = document.getElementById('cancelDeleteBtn');
    if (cancelBtn) cancelBtn.addEventListener('click', () => {
        document.getElementById('deleteConfirmModal').classList.remove('active');
    });
});


// ── 시스템 설정 모달 ─────────────────────────────────────
async function loadConfigIntoForm() {
    try {
        const ifR = await(await fetch('/api/interfaces')).json();
        const sel = $('cfgIface');
        if(ifR.success && ifR.data) {
            sel.innerHTML='<option value="all">자동 선택</option>';
            ifR.data.forEach(i => { const o=document.createElement('option'); o.value=i.name; o.textContent=i.desc||i.name; sel.appendChild(o); });
        }
        const r = await(await fetch('/api/config')).json();
        if(r.success) {
            const d=r.data;
            $('cfgHost').value=d.server?.host||'0.0.0.0';
            $('cfgPort').value=d.server?.port||25565;
            if(d.server?.iface) sel.value = d.server.iface;
        }
    } catch(e) { console.error('Failed to load config', e); }
}

if($('menuSettingsBtn')) $('menuSettingsBtn').addEventListener('click', () => { loadConfigIntoForm(); $('configModal').classList.add('active'); });
if($('closeConfigModal')) $('closeConfigModal').addEventListener('click', () => $('configModal').classList.remove('active'));

if($('saveConfigBtn')) $('saveConfigBtn').addEventListener('click', async () => {
    const cfg = {
        server: { host: $('cfgHost').value.trim(), port: parseInt($('cfgPort').value.trim(), 10) || 25565, iface: $('cfgIface').value==='all'?null:$('cfgIface').value }
    };
    try {
        const r = await (await fetch('/api/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cfg) })).json();
        if(r.success) {
            alert('설정이 저장되었습니다.');
        } else alert('저장 실패: ' + r.error);
    } catch(e) { alert('오류: ' + e.message); }
});

// ── 선택 처리 (Batch) ──────────────────────────────────────
window.showBatchAnalysisUI = function(packets) {
    console.log("showBatchAnalysisUI called with", packets.length);
    const headerTitle = document.querySelector('.panel-header h3');
    if (headerTitle) headerTitle.textContent = '다중 패킷 분석';
    
    $('hexTitle').style.display = 'none';
    $('hexBox').style.display = 'block';
    
    const aiPanel = $('aiPanel');
    const resizer = $('resizer');
    if (aiPanel && aiPanel.classList.contains('collapsed')) {
        aiPanel.classList.remove('collapsed');
        if (resizer) resizer.classList.remove('collapsed');
    }
    
    $('hexBox').innerHTML = `<div style="display: flex; flex-direction: column; gap: 20px; width: 100%;">
        <div style="text-align:center; padding: 20px; background: var(--bg-card); border-radius: var(--radius-md); border: 1px solid var(--border-medium);">
            <div style="font-size: 2.5rem; margin-bottom: 15px;">📊</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: var(--accent-blue);">${packets.length}개의 패킷 선택됨</div>
            <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 8px;">선택한 패킷들을 분석하거나 파일로 내보낼 수 있습니다.</div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px; width: 100%;" id="aiBatchResultArea">
            <button id="aiAnalyzeBatchBtn" class="btn btn-outline" style="width:100%; height:44px; font-size:1rem; border-color: #8b5cf6; color: #8b5cf6;">✨ AI 다중 패킷 연관 분석</button>
            <div id="aiBatchResult" class="markdown-body" style="display:none; background: var(--bg-surface); padding: 20px; border-radius: 8px; border: 1px solid #8b5cf6; font-size: 0.95rem; line-height: 1.6; color: var(--text-primary); max-height: 400px; overflow-y: auto; width: 100%;"></div>
            <button id="exportPcapBtn" class="btn btn-outline btn-cyan" style="width:100%; height:44px; font-size:1rem;">📦 PCAP 내보내기</button>
        </div>
    </div>`;

    $('aiAnalyzeBatchBtn').addEventListener('click', async () => {
        const btn = $('aiAnalyzeBatchBtn');
        const oldTxt = btn.innerHTML;
        btn.innerHTML = '<span class="btn-icon">⏳</span> AI가 패킷들을 분석 중입니다...'; 
        btn.disabled = true;
        try {
            const res = await fetch('/api/ai-analyze', {
                method:'POST',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({packets})
            });
            const r = await res.json();
            const resBox = $('aiBatchResult');
            resBox.style.display = 'block';
            if (r.success) {
                resBox.innerHTML = marked.parse(r.result);
            } else {
                resBox.innerHTML = `<span style="color:var(--accent-red)">오류: ${r.error}</span>`;
            }
        } catch(e) {
            $('aiBatchResult').style.display = 'block';
            $('aiBatchResult').innerHTML = `<span style="color:var(--accent-red)">오류: ${e.message}</span>`;
        } finally { 
            btn.innerHTML = oldTxt; 
            btn.disabled = false; 
        }
    });

    $('exportPcapBtn').addEventListener('click', async () => {
        const btn = $('exportPcapBtn');
        const oldTxt = btn.textContent;
        btn.textContent = '⌛ 생성 중...'; btn.disabled = true;
        try {
            const res = await fetch('/api/export-pcap', {
                method:'POST',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({packets})
            });
            if (res.ok) {
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url;
                a.download = `netscope_export_${Date.now()}.pcap`;
                document.body.appendChild(a); a.click(); a.remove();
            } else { alert('PCAP 내보내기 실패'); }
        } catch(e) { alert('오류: ' + e.message); }
        finally { btn.textContent = oldTxt; btn.disabled = false; }
    });
};

// ── 리사이저 (패널 크기 조절) ─────────────────────────
(function() {
    const resizer=$('resizer'), panel=$('aiPanel'); if(!resizer||!panel) return;
    let isResizing=false, startX, startW;
    resizer.addEventListener('mousedown', e => { isResizing=true; startX=e.clientX; startW=panel.offsetWidth; resizer.classList.add('active'); document.body.style.cursor='col-resize'; e.preventDefault(); });
    document.addEventListener('mousemove', e => { if(!isResizing) return; const w=startW-(e.clientX-startX); panel.style.width=Math.max(280, Math.min(900, w))+'px'; });
    document.addEventListener('mouseup', () => { if(isResizing){isResizing=false; resizer.classList.remove('active'); document.body.style.cursor='';} });
})();

// ── 모달 외부 클릭 닫기 ──────────────────────────────────
document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', e => { if(e.target===overlay) overlay.classList.remove('active'); });
});
