// ═══════════════════════════════════════════════════════════
// NetScope AI - Core JavaScript (WebSocket, Packets, Chart)
// ═══════════════════════════════════════════════════════════

// ── WebSocket ────────────────────────────────────────────
let socket = null;
const _wsH = {};
function connectWS() {
    const p = location.protocol === 'https:' ? 'wss:' : 'ws:';
    socket = new WebSocket(`${p}//${location.host}/ws`);
    socket.onopen = () => { if (_wsH['connect']) _wsH['connect'].forEach(f => f()); };
    socket.onclose = () => { if (_wsH['disconnect']) _wsH['disconnect'].forEach(f => f()); setTimeout(connectWS, 3000); };
    socket.onerror = () => {};
    socket.onmessage = (e) => {
        try {
            const m = JSON.parse(e.data);
            if (m.event && _wsH[m.event]) _wsH[m.event].forEach(f => f(m.data));
        } catch (err) { console.error('WS parse error:', err); }
    };
}
function onSocket(ev, fn) { if (!_wsH[ev]) _wsH[ev] = []; _wsH[ev].push(fn); }
connectWS();

// ── 전역 상태 ────────────────────────────────────────────
let currentMode = 'LIVE', isSaving = false, isPaused = false;
let total = 0, inCount = 0, outCount = 0, ppsIn = 0, ppsOut = 0;
let firstPacket = true, currentPage = 1;
let ipAliases = {}, savedRules = [];
let last100Ips = []; // Top IP 추적용
let _analysisAbort = null;

// ── DOM 참조 ─────────────────────────────────────────────
const $ = id => document.getElementById(id);
window.$ = $;
const packetList = $('packetList'), countTotal = $('count-total');
const countIn = $('count-in'), countOut = $('count-out');
const ppsDisplay = $('pps-display'), statusText = $('status-text');
const tabLive = $('tabLive'), tabDevices = $('tabDevices');
const topTitle = $('topTitle'), chartsGrid = document.querySelector('.charts-grid');
const archiveDateInputs = $('archiveDateInputs');
const pauseBtn = $('pauseBtn');
const maxPacketsSelect = $('maxPacketsSelect');
const applyFilterBtn = $('applyFilterBtn'), resetFilterBtn = $('resetFilterBtn');

// ── 별명 ─────────────────────────────────────────────────
async function fetchAliases() {
    try { const r = await (await fetch('/api/aliases')).json(); if (r.success) ipAliases = r.data || {}; } catch(e) {}
}
function resolveIp(ip) {
    if (!ipAliases[ip]) return ip;
    const name = ipAliases[ip].name;
    if (!name) return ip;
    return `<span title="${ip}" style="color:var(--accent-blue);font-weight:600;">${name}</span>`;
}
fetchAliases();

// ── 테마 ─────────────────────────────────────────────────
(function() {
    const saved = localStorage.getItem('netvisor-theme');
    if (saved) { document.documentElement.setAttribute('data-theme', saved); }
})();
$('themeToggle').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme');
    const next = cur === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('netvisor-theme', next);
    if (typeof trafficChart !== 'undefined' && trafficChart.options) {
        trafficChart.options.scales.y.grid.color = next === 'light' ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.05)';
        trafficChart.options.scales.y.ticks.color = next === 'light' ? '#475569' : '#94A3B8';
        trafficChart.update('none');
    }
    if (typeof topIpChart !== 'undefined' && topIpChart.options) {
        topIpChart.options.scales.x.ticks.color = next === 'light' ? '#64748B' : 'rgba(255,255,255,0.3)';
        topIpChart.options.scales.y.ticks.color = next === 'light' ? '#0F172A' : '#FFFFFF';
        topIpChart.update('none');
    }
});

// ── 연결 상태 ────────────────────────────────────────────
onSocket('disconnect', () => { statusText.textContent = '연결 끊김'; document.querySelector('.status-dot').style.background = 'var(--accent-red)'; });
onSocket('connect', () => { statusText.textContent = '연결됨'; document.querySelector('.status-dot').style.background = 'var(--accent-green)'; });

// ── 탭 전환 ─────────────────────────────────────────────
maxPacketsSelect.addEventListener('change', () => { const m = parseInt(maxPacketsSelect.value, 10); while (packetList.children.length > m) packetList.lastChild.remove(); });

function setMode(mode) {
    if (mode === currentMode) return;
    currentMode = mode; packetList.innerHTML = '';
    
    // 탭 액티브 상태 초기화
    if (tabLive) tabLive.classList.remove('active'); 
    const tabDevices = $('tabDevices');
    if (tabDevices) tabDevices.classList.remove('active');
    const tabSuspicious = $('tabSuspicious');
    if (tabSuspicious) tabSuspicious.classList.remove('active');

    const delBtn = $('deleteSelectedBtn'), selAll = $('selectAllCheckbox');
    const archMax = $('archiveMaxPacketsSelect'), pgWrap = $('paginationWrap'), batchBtn = $('batchAnalyzeBtn');
    if (selAll) selAll.checked = false;
    const topSubtitle = $('topSubtitle');

    const devicesView = $('devicesView');
    const suspiciousIpView = $('suspiciousIpView');
    const packetSection = document.querySelector('.packet-section');
    const aliasFormContainer = $('aliasFormContainer');

    if (mode === 'LIVE') {
        tabLive.classList.add('active'); topTitle.textContent = '실시간 패킷 모니터';
        if(topSubtitle) topSubtitle.textContent = '네트워크 트래픽을 실시간으로 캡처하고 분석합니다.';
        if (chartsGrid) chartsGrid.style.display = 'grid';
        if (devicesView) devicesView.style.display = 'none';
        if (suspiciousIpView) suspiciousIpView.style.display = 'none';
        if (aliasFormContainer) aliasFormContainer.style.display = 'none';
        if (packetSection) packetSection.style.display = 'flex';
        pauseBtn.style.display = 'flex';
        archiveDateInputs.style.display = 'none';
        if (delBtn) delBtn.style.display = 'none'; if (selAll) selAll.disabled = true;
        if (maxPacketsSelect) maxPacketsSelect.style.display = 'flex';
        if (archMax) archMax.style.display = 'none'; if (pgWrap) pgWrap.style.display = 'none';
        if (batchBtn) batchBtn.style.display = 'none';
        if ($('colReasonHeader')) {
            $('colReasonHeader').style.display = 'none';
            $('colReasonHeader').closest('.packet-header').classList.remove('with-reason');
        }
        $('filterIp').value = '';
        firstPacket = true; sendFilter();
    } else if (mode === 'DEVICES') {
        $('tabDevices').classList.add('active'); topTitle.textContent = '등록된 IP';
        if(topSubtitle) topSubtitle.textContent = '등록된 IP와의 트래픽 내역을 확인합니다.';
        if ($('backToDevicesBtn')) $('backToDevicesBtn').style.display = 'none';
        if ($('aiRiskAssessBtn')) $('aiRiskAssessBtn').style.display = 'none';
        if (chartsGrid) chartsGrid.style.display = 'none';
        if (devicesView) devicesView.style.display = 'flex';
        if (suspiciousIpView) suspiciousIpView.style.display = 'none';
        if (aliasFormContainer) aliasFormContainer.style.display = 'block';
        if (packetSection) packetSection.style.display = 'none';
        pauseBtn.style.display = 'none';
        $('filterIp').value = '';
        renderDevicesGrid();
    } else if (mode === 'DEVICE_DETAIL') {
        $('tabDevices').classList.add('active'); 
        const filterIp = $('filterIp').value;
        const aliasData = ipAliases[filterIp] || {};
        const devName = aliasData.name || aliasData || '알 수 없는 장비';
        
        topTitle.textContent = `장비 상세 조회: ${devName}`;
        if(topSubtitle) topSubtitle.textContent = `IP: ${filterIp} 와 연관된 모든 패킷 히스토리입니다.`;
        if ($('backToDevicesBtn')) {
            $('backToDevicesBtn').style.display = 'inline-flex';
            $('backToDevicesBtn').onclick = () => setMode('DEVICES');
        }
        if ($('aiRiskAssessBtn')) {
            $('aiRiskAssessBtn').style.display = 'inline-flex';
            $('aiRiskAssessBtn').onclick = () => showAiRiskAssess(filterIp);
        }
        if (chartsGrid) chartsGrid.style.display = 'none';
        if (devicesView) devicesView.style.display = 'none';
        if (suspiciousIpView) suspiciousIpView.style.display = 'none';
        if (aliasFormContainer) aliasFormContainer.style.display = 'none';
        if (packetSection) packetSection.style.display = 'flex';
        pauseBtn.style.display = 'none';
        archiveDateInputs.style.display = 'flex';
        if (delBtn) delBtn.style.display = 'flex'; if (selAll) selAll.disabled = false;
        if (maxPacketsSelect) maxPacketsSelect.style.display = 'none';
        if (archMax) archMax.style.display = 'flex'; if (batchBtn) batchBtn.style.display = 'inline-block';
        if ($('colReasonHeader')) {
            $('colReasonHeader').style.display = 'none';
            $('colReasonHeader').closest('.packet-header').classList.remove('with-reason');
        }
        currentPage = 1; sendFilter();
    } else if (mode === 'SUSPICIOUS') {
        if (tabSuspicious) tabSuspicious.classList.add('active'); 
        topTitle.textContent = '🚨 의심 트래픽 탐지';
        if(topSubtitle) topSubtitle.textContent = '의심 트래픽이 발생한 기기 목록입니다. 상세 내역을 보려면 기기를 선택하세요.';
        if ($('backToDevicesBtn')) $('backToDevicesBtn').style.display = 'none';
        if ($('aiRiskAssessBtn')) $('aiRiskAssessBtn').style.display = 'none';
        if (chartsGrid) chartsGrid.style.display = 'none';
        if (devicesView) devicesView.style.display = 'none';
        if (suspiciousIpView) suspiciousIpView.style.display = 'flex';
        if (aliasFormContainer) aliasFormContainer.style.display = 'none';
        if (packetSection) packetSection.style.display = 'none';
        pauseBtn.style.display = 'none';
        $('filterIp').value = '';
        renderSuspiciousIpGrid();
    } else if (mode === 'SUSPICIOUS_DETAIL') {
        if (tabSuspicious) tabSuspicious.classList.add('active'); 
        const filterIp = $('filterIp').value;
        topTitle.textContent = '🚨 의심 트래픽 상세 조회';
        if(topSubtitle) topSubtitle.textContent = `IP: ${filterIp} 에서 발생한 의심 패킷 기록입니다.`;
        if ($('backToDevicesBtn')) {
            $('backToDevicesBtn').style.display = 'inline-flex';
            $('backToDevicesBtn').onclick = () => setMode('SUSPICIOUS');
        }
        if ($('aiRiskAssessBtn')) {
            $('aiRiskAssessBtn').style.display = 'inline-flex';
            $('aiRiskAssessBtn').onclick = () => showAiRiskAssess(filterIp);
        }
        if (chartsGrid) chartsGrid.style.display = 'none';
        if (devicesView) devicesView.style.display = 'none';
        if (suspiciousIpView) suspiciousIpView.style.display = 'none';
        if (aliasFormContainer) aliasFormContainer.style.display = 'none';
        if (packetSection) packetSection.style.display = 'flex';
        pauseBtn.style.display = 'none';
        archiveDateInputs.style.display = 'flex';
        if (delBtn) delBtn.style.display = 'flex'; if (selAll) selAll.disabled = false;
        if (maxPacketsSelect) maxPacketsSelect.style.display = 'none';
        if (archMax) archMax.style.display = 'flex'; if (batchBtn) batchBtn.style.display = 'inline-block';
        if ($('colReasonHeader')) {
            $('colReasonHeader').style.display = 'block';
            $('colReasonHeader').closest('.packet-header').classList.add('with-reason');
        }
        currentPage = 1; sendFilter();
    }
}
tabLive.addEventListener('click', () => {
    if ($('backToDevicesBtn')) $('backToDevicesBtn').style.display = 'none';
    setMode('LIVE');
});
if($('tabDevices')) $('tabDevices').addEventListener('click', () => setMode('DEVICES'));
if($('tabSuspicious')) $('tabSuspicious').addEventListener('click', () => setMode('SUSPICIOUS'));

function renderDevicesGrid() {
    const grid = $('devicesGrid');
    if (!grid) return;
    grid.innerHTML = '';
    const aliases = Object.keys(ipAliases);
    
    if (aliases.length === 0) {
        grid.innerHTML = `<div class="empty-state" style="padding: 40px;">
            <div class="empty-icon">🔌</div>
            <div class="empty-title">등록된 장비가 없습니다.</div>
            <div class="empty-desc">우측 상단의 버튼을 눌러 관리할 장비를 추가해주세요.</div>
        </div>`;
        return;
    }
    
    aliases.forEach(ip => {
        const data = ipAliases[ip] || {};
        const isAutoDetected = !data.name;
        const name = data.name || ip;
        const policy = data.policy || 'SAVE_ALL';
        const pLabel = policy === 'SAVE_ALL' ? '전부 저장' : policy === 'DO_NOT_SAVE' ? '저장 안함' : '자동 (AI)';
        const pColor = policy === 'SAVE_ALL' ? 'var(--accent-green)' : policy === 'DO_NOT_SAVE' ? 'var(--accent-amber)' : 'var(--accent-blue)';
        
        const description = data.description || '';
        
        const row = document.createElement('div');
        row.className = 'device-list-item';
        if (isAutoDetected) {
            row.style.borderLeft = '3px solid var(--accent-red)';
            row.style.background = 'rgba(239, 68, 68, 0.02)';
        }
        
        row.innerHTML = `
            <div class="device-list-info">
                <div class="device-list-icon" style="${isAutoDetected ? 'background: rgba(239, 68, 68, 0.1); border-color: rgba(239, 68, 68, 0.3);' : ''}">${isAutoDetected ? '🚨' : '💻'}</div>
                <div class="device-list-text">
                    <div class="device-list-name" style="display:flex; align-items:center; gap:8px;">
                        ${name}
                        ${isAutoDetected ? '<span style="font-size: 0.7rem; padding: 3px 6px; background: rgba(239, 68, 68, 0.15); color: var(--accent-red); border-radius: 4px; font-weight: 800; border: 1px solid rgba(239, 68, 68, 0.2);">의심 탐지됨</span>' : ''}
                    </div>
                    <div class="device-list-ip">${ip}</div>
                    ${description ? `<div class="device-list-desc" style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 4px; background: rgba(255,255,255,0.05); padding: 4px 8px; border-radius: 4px; border-left: 2px solid var(--accent-purple);">${description}</div>` : ''}
                </div>
            </div>
            <div class="device-list-status" style="display: flex; gap: 10px; align-items: center;">
                <select class="policy-select input-lg" data-ip="${ip}" style="width: 130px;">
                    <option value="SAVE_ALL" ${policy === 'SAVE_ALL' ? 'selected' : ''}>전부 저장</option>
                    <option value="DO_NOT_SAVE" ${policy === 'DO_NOT_SAVE' ? 'selected' : ''}>저장 안함</option>
                    <option value="AUTO" ${policy === 'AUTO' ? 'selected' : ''}>자동 (AI)</option>
                </select>
                <button class="btn btn-secondary btn-edit" data-ip="${ip}" style="box-shadow: none;">수정</button>
                <button class="btn btn-primary btn-delete" data-ip="${ip}" style="background-color: var(--accent-red); box-shadow: none;">삭제</button>
            </div>
        `;
        
        // 클릭 시 패킷 상세 (단, 삭제버튼/select/input 클릭 시에는 제외)
        row.addEventListener('click', (e) => {
            if (e.target.tagName === 'BUTTON' || e.target.tagName === 'SELECT' || e.target.tagName === 'OPTION' || e.target.tagName === 'INPUT') return;
            $('filterIp').value = ip;
            setMode('DEVICE_DETAIL');
        });

        const sel = row.querySelector('.policy-select');
        sel.addEventListener('change', async (e) => {
            const newPolicy = e.target.value;
            try {
                await fetch('/api/aliases', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip: ip, name: name, policy: newPolicy, desc: description})
                });
                ipAliases[ip].policy = newPolicy;
                renderDevicesGrid(); // UI 갱신
            } catch(err) {}
        });

        const editBtn = row.querySelector('.btn-edit');
        let isEditing = false;
        
        editBtn.addEventListener('click', async (e) => {
            e.stopPropagation();
            
            const infoDiv = row.querySelector('.device-list-text');
            if (!isEditing) {
                // Edit mode
                isEditing = true;
                editBtn.textContent = '저장';
                editBtn.style.backgroundColor = 'var(--accent-blue)';
                editBtn.style.color = '#fff';
                
                infoDiv.innerHTML = `
                    <input type="text" class="edit-name filter-input" value="${name}" style="margin-bottom: 6px; width: 100%; border-bottom: 1px solid var(--border-medium); border-radius: 0; padding: 4px 2px; height: 28px;" placeholder="장비 이름">
                    <input type="text" class="edit-desc filter-input" value="${description}" placeholder="설명 (선택)..." style="width: 100%; border-bottom: 1px solid var(--border-medium); border-radius: 0; padding: 4px 2px; height: 28px; font-size: 0.85rem;">
                `;
            } else {
                // Save mode
                const newName = infoDiv.querySelector('.edit-name').value.trim();
                const newDesc = infoDiv.querySelector('.edit-desc').value.trim();
                if (!newName) return alert("이름을 입력하세요.");
                
                try {
                    const r = await (await fetch('/api/aliases', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ip: ip, name: newName, policy: policy, desc: newDesc})
                    })).json();
                    
                    if (r.success) {
                        ipAliases[ip] = {name: newName, policy: policy, description: newDesc};
                        renderDevicesGrid(); // Re-render to show updated text
                    } else {
                        alert(r.error);
                    }
                } catch(err) {
                    alert("수정 실패");
                }
            }
        });

        const delBtn = row.querySelector('.btn-delete');
        delBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (window.removeAlias) window.removeAlias(ip);
        });

        grid.appendChild(row);
    });
}

async function renderSuspiciousIpGrid() {
    const grid = $('suspiciousIpGrid');
    if (!grid) return;
    grid.innerHTML = '<div class="empty-state">조회 중...</div>';
    
    try {
        const res = await (await fetch('/api/suspicious-ips')).json();
        if (!res.success || !res.data || res.data.length === 0) {
            grid.innerHTML = `<div class="empty-state" style="padding: 40px;">
                <div class="empty-icon">🛡️</div>
                <div class="empty-title">감지된 의심 트래픽이 없습니다.</div>
                <div class="empty-desc">네트워크가 안전한 상태입니다.</div>
            </div>`;
            return;
        }

        grid.innerHTML = '';
        res.data.forEach(item => {
            const ip = item.ip;
            const aliasData = ipAliases[ip] || {};
            const name = aliasData.name || '';
            const description = aliasData.description || '';
            const policy = aliasData.policy || 'SAVE_ALL';
            const nameDisplay = name ? ` (${name})` : '';
            
            const card = document.createElement('div');
            card.className = 'device-list-item suspicious';
            card.style.cursor = 'pointer';
            card.innerHTML = `
                <div class="device-list-info">
                    <div class="device-list-icon" style="background: rgba(244, 63, 94, 0.1); color: #f43f5e; border: 1px solid rgba(244, 63, 94, 0.3);">🚨</div>
                    <div class="device-list-text">
                        <div class="device-list-name" style="display:flex; align-items:center; gap:8px;">
                            ${ip}${nameDisplay}
                            <span class="badge" style="font-size:0.7rem; background:#f43f5e; color:#fff; font-weight:normal;">의심 패킷 ${item.count}건</span>
                        </div>
                        <div class="device-list-desc" style="font-size:0.85rem; color:var(--text-secondary); font-family:var(--font-mono); margin-top:4px;">
                            최종 감지: ${item.last_seen}
                        </div>
                        ${description ? `<div class="device-list-desc" style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 4px; background: rgba(255,255,255,0.05); padding: 4px 8px; border-radius: 4px; border-left: 2px solid var(--accent-purple);">${description}</div>` : ''}
                    </div>
                </div>
                <div class="device-list-status" style="display: flex; gap: 10px; align-items: center;">
                    <select class="policy-select input-lg" data-ip="${ip}" style="width: 130px;">
                        <option value="SAVE_ALL" ${policy === 'SAVE_ALL' ? 'selected' : ''}>전부 저장</option>
                        <option value="DO_NOT_SAVE" ${policy === 'DO_NOT_SAVE' ? 'selected' : ''}>저장 안함</option>
                        <option value="AUTO" ${policy === 'AUTO' ? 'selected' : ''}>자동 (AI)</option>
                    </select>
                    <button class="btn btn-secondary btn-edit" data-ip="${ip}" style="box-shadow: none;">수정</button>
                    <button class="btn btn-primary btn-delete" data-ip="${ip}" style="background-color: var(--accent-red); box-shadow: none;">삭제</button>
                    <span style="color:var(--text-secondary); font-size:0.9rem; margin-left:10px;">상세 ➔</span>
                </div>
            `;

            card.addEventListener('click', (e) => {
                if (e.target.tagName === 'BUTTON' || e.target.tagName === 'SELECT' || e.target.tagName === 'OPTION' || e.target.tagName === 'INPUT') return;
                $('filterIp').value = ip;
                setMode('SUSPICIOUS_DETAIL');
            });

            const sel = card.querySelector('.policy-select');
            sel.addEventListener('change', async (e) => {
                const newPolicy = e.target.value;
                try {
                    await fetch('/api/aliases', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ip: ip, name: name, policy: newPolicy, desc: description})
                    });
                    ipAliases[ip] = ipAliases[ip] || {};
                    ipAliases[ip].policy = newPolicy;
                    renderSuspiciousIpGrid(); // UI 갱신
                } catch(err) {}
            });

            const editBtn = card.querySelector('.btn-edit');
            let isEditing = false;
            
            editBtn.addEventListener('click', async (e) => {
                e.stopPropagation();
                
                const infoDiv = card.querySelector('.device-list-text');
                if (!isEditing) {
                    isEditing = true;
                    editBtn.textContent = '저장';
                    editBtn.style.backgroundColor = 'var(--accent-blue)';
                    editBtn.style.color = '#fff';
                    
                    infoDiv.innerHTML = `
                        <input type="text" class="edit-name filter-input" value="${name}" style="margin-bottom: 6px; width: 100%; border-bottom: 1px solid var(--border-medium); border-radius: 0; padding: 4px 2px; height: 28px;" placeholder="장비 이름">
                        <input type="text" class="edit-desc filter-input" value="${description}" placeholder="설명 (선택)..." style="width: 100%; border-bottom: 1px solid var(--border-medium); border-radius: 0; padding: 4px 2px; height: 28px; font-size: 0.85rem;">
                    `;
                } else {
                    const newName = infoDiv.querySelector('.edit-name').value.trim();
                    const newDesc = infoDiv.querySelector('.edit-desc').value.trim();
                    if (!newName) return alert("이름을 입력하세요.");
                    
                    try {
                        const r = await (await fetch('/api/aliases', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({ip: ip, name: newName, policy: policy, desc: newDesc})
                        })).json();
                        
                        if (r.success) {
                            ipAliases[ip] = {name: newName, policy: policy, description: newDesc};
                            renderSuspiciousIpGrid();
                        } else {
                            alert(r.error);
                        }
                    } catch(err) {
                        alert("수정 실패");
                    }
                }
            });

            const delBtn = card.querySelector('.btn-delete');
            delBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                if (window.removeAlias) window.removeAlias(ip);
                setTimeout(renderSuspiciousIpGrid, 100);
            });

            grid.appendChild(card);
        });
    } catch(err) {
        grid.innerHTML = `<div class="empty-state">데이터를 불러오는 데 실패했습니다.</div>`;
    }
}

// ── 장비 등록 및 삭제 ───────────────────────────────────────────
if ($('addAliasBtn')) {
    $('addAliasBtn').addEventListener('click', async () => {
        const ip = $('aliasIp').value.trim();
        const name = $('aliasName').value.trim();
        const desc = $('aliasDesc').value.trim();
        const policy = $('aliasPolicy').value;
        
        if (!ip) return alert("IP 주소를 입력하세요.");
        
        try {
            const r = await (await fetch('/api/aliases', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, name, desc, policy })
            })).json();
            
            if (r.success) {
                ipAliases[ip] = { name: name, policy: policy, description: desc };
                $('aliasIp').value = '';
                $('aliasName').value = '';
                $('aliasDesc').value = '';
                $('aliasPolicy').value = 'SAVE_ALL';
                renderDevicesGrid();
                renderSuspiciousIpGrid();
            } else {
                alert(r.error);
            }
        } catch(err) {
            alert("장비 등록 실패: " + err.message);
        }
    });
}

window.removeAlias = function(ip) {
    const modal = $('deleteConfirmModal');
    const targetIpSpan = $('deleteTargetIp');
    if (!modal || !targetIpSpan) return;
    
    targetIpSpan.textContent = ip;
    modal.classList.add('active');
    
    const cancelBtn = $('cancelDeleteBtn');
    const confirmBtn = $('confirmDeleteBtn');
    
    const cleanup = () => {
        modal.classList.remove('active');
        cancelBtn.removeEventListener('click', onCancel);
        confirmBtn.removeEventListener('click', onConfirm);
    };
    
    const onCancel = () => { cleanup(); };
    
    const onConfirm = async () => {
        try {
            const r = await (await fetch('/api/aliases', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            })).json();
            
            if (r.success) {
                delete ipAliases[ip];
                if (currentMode === 'DEVICES') renderDevicesGrid();
                if (currentMode === 'SUSPICIOUS') renderSuspiciousIpGrid();
                cleanup();
            } else {
                alert('삭제 실패: ' + r.error);
                cleanup();
            }
        } catch(err) {
            alert('삭제 오류: ' + err.message);
            cleanup();
        }
    };
    
    cancelBtn.addEventListener('click', onCancel);
    confirmBtn.addEventListener('click', onConfirm);
};

// ── 삭제 ─────────────────────────────────────────────────
const selectAllCb = $('selectAllCheckbox'), deleteSelBtn = $('deleteSelectedBtn');
if (selectAllCb) selectAllCb.addEventListener('change', e => { 
    document.querySelectorAll('.row-checkbox').forEach(cb => cb.checked = e.target.checked);
    updateSelectionUI();
});
document.addEventListener('change', e => {
    if (e.target.classList.contains('row-checkbox')) {
        updateSelectionUI();
    }
});

window.updateSelectionUI = function() {
    const checked = document.querySelectorAll('.row-checkbox:checked');
    if (checked.length >= 2) {
        const packets = Array.from(checked).map(cb => {
            const row = cb.closest('.packet-row');
            return row && row.dataset.pkt ? JSON.parse(row.dataset.pkt) : null;
        }).filter(p => p !== null);
        if (typeof showBatchAnalysisUI === 'function') showBatchAnalysisUI(packets);
    } else if (checked.length === 1) {
        const row = checked[0].closest('.packet-row');
        if (row && row.dataset.pkt) showAnalysis(JSON.parse(row.dataset.pkt));
    } else {
        // 선택된 게 없으면 (필요시 비움)
    }
};
if (deleteSelBtn) deleteSelBtn.addEventListener('click', async () => {
    const checked = document.querySelectorAll('.row-checkbox:checked');
    if (!checked.length) return alert('삭제할 패킷을 선택해주세요.');
    if (!confirm(`선택한 ${checked.length}개의 패킷을 영구 삭제하시겠습니까?`)) return;
    const ids = Array.from(checked).map(cb => parseInt(cb.value, 10));
    try {
        const r = await (await fetch('/api/delete-packets', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({db_type:currentMode, ids}) })).json();
        if (r.success) { if (selectAllCb) selectAllCb.checked = false; sendFilter(); } else alert('삭제 실패: ' + r.error);
    } catch(e) { alert('삭제 오류: ' + e.message); }
});

// ── 저장/일시정지 ────────────────────────────────────────
pauseBtn.addEventListener('click', async () => {
    isPaused = !isPaused;
    pauseBtn.classList.toggle('paused', isPaused);
    const txt = pauseBtn.querySelector('.btn-text');
    const icn = pauseBtn.querySelector('.btn-icon');
    if(txt) txt.textContent = isPaused ? '계속 (일시정지됨)' : '일시정지';
    if(icn) icn.textContent = isPaused ? '▶' : '⏸';
    try { await fetch('/api/toggle-pause', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({paused:isPaused})}); } catch(e) {}
});

// ── 필터 ─────────────────────────────────────────────────
async function sendFilter() {
    const f = { ip:$('filterIp').value, port:$('filterPort').value, proto:$('filterProto').value, dir:$('filterDir').value, min_size:$('filterMinSize').value, max_size:$('filterMaxSize').value };
    if (currentMode === 'LIVE') {
        const pw = $('paginationWrap'); if (pw) pw.style.display = 'none';
        try { await fetch('/api/set-filter', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(f)}); packetList.innerHTML = '<div class="empty-state"><div class="icon" style="font-size:2rem">📡</div><div>필터 조건에 맞는 패킷을 기다리는 중...</div></div>'; } catch(e) {}
    } else {
        const archMax = $('archiveMaxPacketsSelect');
        const limit = parseInt(archMax ? archMax.value : '200', 10);
        f.start_time = ($('filterStart').value || '').replace('T', ' ');
        f.end_time = ($('filterEnd').value || '').replace('T', ' ');
        f.limit = limit; f.page = currentPage;
        packetList.innerHTML = '<div class="empty-state"><div class="icon">🔍</div><div>조회 중...</div></div>';
        try {
            let ep = '/api/history';
            if (currentMode === 'DEVICE_DETAIL') ep = '/api/device-history';
            else if (currentMode === 'SUSPICIOUS_DETAIL') ep = '/api/suspicious-history';
            
            const res = await (await fetch(ep, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(f)})).json();
            packetList.innerHTML = '';
            if (!res.data || !res.data.length) { packetList.innerHTML = '<div class="empty-state"><div>해당 조건에 저장된 패킷이 없습니다.</div></div>'; $('paginationWrap').style.display = 'none'; return; }
            res.data.forEach(d => {
                const isSuspicious = d.reason && d.reason.length > 0;
                const row = document.createElement('div'); 
                row.className = 'packet-row' + (isSuspicious ? ' suspicious' : '') + (currentMode === 'SUSPICIOUS_DETAIL' ? ' with-reason' : '');
                row.dataset.pkt = JSON.stringify(d);
                
                let reasonHtml = '';
                if (currentMode === 'SUSPICIOUS_DETAIL') {
                    reasonHtml = `<div class="col-reason"><span class="suspicious-badge">${d.reason || '의심 감지'}</span></div>`;
                }

                row.innerHTML = `<div class="col-checkbox"><input type="checkbox" class="row-checkbox" value="${d.no}"></div>
                    <div class="col-no">${d.no}</div>
                    <div class="col-time">${d.time}</div>
                    <div class="col-src">${resolveIp(d.src)}</div>
                    <div class="col-dst">${resolveIp(d.dst)}</div>
                    <div class="col-proto">${protoBadge(d.proto)}</div>
                    <div class="col-dir">${dirBadge(d.direction)}</div>
                    <div class="col-size">${d.len}</div>
                    ${reasonHtml}`;
                row.addEventListener('click', e => { if (e.target.type==='checkbox') return; document.querySelectorAll('.packet-row').forEach(r=>r.classList.remove('selected')); row.classList.add('selected'); showAnalysis(d); });
                packetList.appendChild(row);
            });
            renderPagination(res.total, limit);
            if(typeof updateSelectionUI === 'function') updateSelectionUI();
        } catch(e) { packetList.innerHTML = '<div class="empty-state"><div>오류 발생</div></div>'; $('paginationWrap').style.display = 'none'; }
    }
}

function renderPagination(total, limit) {
    const pw = $('paginationWrap'); if (!pw) return;
    const tp = Math.ceil(total / limit);
    if (tp <= 1) { pw.style.display = 'none'; return; }
    pw.style.display = 'flex'; pw.innerHTML = '';
    const mkBtn = (txt, pg, dis=false, act=false) => { const b = document.createElement('button'); b.className = 'page-btn'; if(act) b.classList.add('active'); b.textContent = txt; b.disabled = dis; b.addEventListener('click', () => { currentPage = pg; sendFilter(); }); return b; };
    pw.appendChild(mkBtn('<<', 1, currentPage===1)); pw.appendChild(mkBtn('<', currentPage-1, currentPage===1));
    let sp = Math.max(1, currentPage-5), ep = Math.min(tp, sp+9); if (ep-sp<9) sp = Math.max(1, ep-9);
    for (let i=sp; i<=ep; i++) pw.appendChild(mkBtn(i, i, false, i===currentPage));
    pw.appendChild(mkBtn('>', currentPage+1, currentPage===tp)); pw.appendChild(mkBtn('>>', tp, currentPage===tp));
}

if ($('archiveMaxPacketsSelect')) $('archiveMaxPacketsSelect').addEventListener('change', () => { currentPage=1; sendFilter(); });
applyFilterBtn.addEventListener('click', () => { currentPage=1; sendFilter(); });
resetFilterBtn.addEventListener('click', () => { ['filterIp','filterPort','filterProto','filterDir','filterMinSize','filterMaxSize','filterStart','filterEnd'].forEach(id => { const el=$(id); if(el) el.value=''; }); currentPage=1; sendFilter(); });

// ── 배지 헬퍼 ────────────────────────────────────────────
function protoBadge(p) { return p==='TCP' ? '<span class="badge badge-tcp">TCP</span>' : p==='UDP' ? '<span class="badge badge-udp">UDP</span>' : `<span class="badge" style="background:var(--bg-tertiary); color:var(--text-secondary);">${p}</span>`; }
function dirBadge(d) { return d==='INBOUND' ? '<span class="badge badge-in">↓ IN</span>' : d==='OUTBOUND' ? '<span class="badge badge-out">↑ OUT</span>' : '<span class="badge" style="color:var(--text-dim)">— —</span>'; }

// ── Chart.js ─────────────────────────────────────────────
const ctx = $('trafficChart').getContext('2d');
const gradientIn = ctx.createLinearGradient(0, 0, 0, 140);
gradientIn.addColorStop(0, 'hsla(150, 80%, 50%, 0.2)');
gradientIn.addColorStop(1, 'transparent');

const gradientOut = ctx.createLinearGradient(0, 0, 0, 140);
gradientOut.addColorStop(0, 'hsla(0, 85%, 65%, 0.15)');
gradientOut.addColorStop(1, 'transparent');

const CHART_PTS = 30;
const trafficChart = new Chart(ctx, {
    type: 'line',
    data: { labels: Array(CHART_PTS).fill(''), datasets: [
        { label:'수신', data:Array(CHART_PTS).fill(0), borderColor:'hsl(150, 80%, 50%)', backgroundColor:gradientIn, borderWidth:2.5, tension:0.45, fill:true, pointRadius:0, capBezierPoints:true },
        { label:'송신', data:Array(CHART_PTS).fill(0), borderColor:'hsl(0, 85%, 65%)', backgroundColor:gradientOut, borderWidth:2.5, tension:0.45, fill:true, pointRadius:0, capBezierPoints:true }
    ]},
    options: { responsive:true, maintainAspectRatio:false, animation:{duration:400, easing:'easeOutQuart'}, interaction:{mode:'index',intersect:false}, plugins:{legend:{display:false}},
        scales: { x:{display:false}, y:{ beginAtZero:true, grid:{color:'rgba(255,255,255,0.03)', drawBorder:false}, ticks:{color:'rgba(255,255,255,0.3)', font:{size:10, family:'JetBrains Mono'}, maxTicksLimit:4, precision:0} } }
    }
});

const topIpCtx = $('topIpChart').getContext('2d');
const gradientBar = topIpCtx.createLinearGradient(0, 0, 400, 0);
gradientBar.addColorStop(0, 'hsla(210, 100%, 60%, 0.4)');
gradientBar.addColorStop(1, 'hsla(185, 100%, 50%, 0.1)');

const topIpChart = new Chart(topIpCtx, {
    type: 'bar',
    data: { labels: [], datasets: [{ data: [], backgroundColor: gradientBar, borderColor: 'hsla(210, 100%, 60%, 0.5)', borderWidth: 1, borderRadius: 6, barThickness: 12 }] },
    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, animation: { duration: 600 }, plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true, grid: { display: false }, ticks: { color: 'rgba(255,255,255,0.3)', font: { size: 9 } } }, y: { grid: { display: false }, ticks: { color: '#FFFFFF', font: { size: 10, weight: '600', family: 'JetBrains Mono' } } } }
    }
});

const INT_MS = 200;
setInterval(() => {
    trafficChart.data.datasets[0].data.push(ppsIn); trafficChart.data.datasets[0].data.shift();
    trafficChart.data.datasets[1].data.push(ppsOut); trafficChart.data.datasets[1].data.shift();
    trafficChart.update('none');
    ppsDisplay.textContent = ((ppsIn + ppsOut) * (1000/INT_MS)).toFixed(0);
    ppsIn = 0; ppsOut = 0;
}, INT_MS);

// Top IP 업데이트 (1초마다)
setInterval(() => {
    if (!last100Ips.length) return;
    const freq = {};
    last100Ips.forEach(ip => { if(ip && ip !== '0.0.0.0') freq[ip] = (freq[ip] || 0) + 1; });
    const sorted = Object.entries(freq).sort((a,b) => b[1] - a[1]).slice(0, 5);
    
    topIpChart.data.labels = sorted.map(x => x[0]);
    topIpChart.data.datasets[0].data = sorted.map(x => x[1]);
    topIpChart.update('none');
}, 1000);

// ── 패킷 수신 ───────────────────────────────────────────
onSocket('new_packet', d => {
    const row = processPacketData(d);
    if (row) {
        packetList.prepend(row);
        trimPacketList();
        if(typeof updateSelectionUI === 'function') updateSelectionUI();
    }
});

onSocket('new_packets', arr => { 
    if (Array.isArray(arr) && arr.length > 0) {
        const frag = document.createDocumentFragment();
        // 역순으로 렌더링해야 최신 패킷이 맨 위에 위치함
        [...arr].reverse().forEach(d => {
            const row = processPacketData(d);
            if (row) frag.appendChild(row);
        });
        packetList.prepend(frag);
        trimPacketList();
        if(typeof updateSelectionUI === 'function') updateSelectionUI();
    }
});

function processPacketData(data) {
    // 전역 통계 및 차트 데이터는 어떤 모드에서도 항상 업데이트
    const dir = data.direction || 'OTHER';
    total++; 
    if (dir==='INBOUND'){ inCount++; ppsIn++; } 
    else if(dir==='OUTBOUND'){ outCount++; ppsOut++; } 
    else ppsIn++;
    
    countTotal.textContent = total; 
    countIn.textContent = inCount; 
    countOut.textContent = outCount;

    // Top IP 추적 (최근 100개 패킷)
    last100Ips.unshift(data.src, data.dst);
    if (last100Ips.length > 200) last100Ips = last100Ips.slice(0, 200);

    // Toast notification for suspicious packets in any mode
    if (data.suspicious) {
        showSuspiciousToast(data);
    }

    // 현재 LIVE 모드가 아니면 리스트 렌더링은 스킵
    if (currentMode !== 'LIVE') return null;
    
    if (firstPacket) { packetList.innerHTML = ''; firstPacket = false; }

    let timeStr = data.time || '';
    if (!timeStr.includes('-') && !isNaN(parseFloat(timeStr))) {
        const d = new Date(parseFloat(timeStr)*1000);
        timeStr = `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;
    }

    const isSuspicious = data.suspicious;
    const row = document.createElement('div');
    row.className = 'packet-row' + (data.highlight ? ' highlighted-packet' : '') + (isSuspicious ? ' suspicious' : '');
    row.dataset.pkt = JSON.stringify(data);
    row.innerHTML = `<div class="col-checkbox"><input type="checkbox" class="row-checkbox" value="${data.no}"></div>
        <div class="col-no">${data.no}</div>
        <div class="col-time">${timeStr}</div>
        <div class="col-src">${resolveIp(data.src)}</div>
        <div class="col-dst">${resolveIp(data.dst)}</div>
        <div class="col-proto">${protoBadge(data.proto)}</div>
        <div class="col-dir">${dirBadge(dir)}</div>
        <div class="col-size">${data.len}</div>
        <div class="col-reason" style="display:none;"></div>`;
    row.addEventListener('click', e => { if(e.target.type==='checkbox') return; document.querySelectorAll('.packet-row').forEach(r=>r.classList.remove('selected')); row.classList.add('selected'); showAnalysis(data); });
    
    return row;
}

function showSuspiciousToast(data) {
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.style.cssText = 'position:fixed; bottom:20px; right:20px; z-index:9999; display:flex; flex-direction:column; gap:10px; pointer-events:none;';
        document.body.appendChild(container);
    }
    
    const toast = document.createElement('div');
    toast.style.cssText = 'background: rgba(244, 63, 94, 0.95); color: white; padding: 12px 16px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); backdrop-filter: blur(4px); border: 1px solid rgba(255,255,255,0.1); transform: translateX(120%); transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275); display: flex; align-items: center; gap: 10px; pointer-events:auto; cursor:pointer; min-width:300px;';
    toast.innerHTML = `
        <div style="font-size:1.5rem;">🚨</div>
        <div style="flex:1;">
            <div style="font-weight:700; font-size:0.95rem; margin-bottom:2px;">의심 트래픽 감지</div>
            <div style="font-size:0.8rem; opacity:0.9;">${data.suspicion_reason || '비정상 패턴 발견'} (${data.src} → ${data.dst})</div>
        </div>
    `;
    
    toast.addEventListener('click', () => {
        $('filterIp').value = data.src;
        setMode('SUSPICIOUS_DETAIL');
        toast.style.transform = 'translateX(120%)';
        setTimeout(() => toast.remove(), 300);
    });

    container.appendChild(toast);
    
    // Slide in
    requestAnimationFrame(() => {
        toast.style.transform = 'translateX(0)';
    });
    
    // Slide out after 5 seconds
    setTimeout(() => {
        toast.style.transform = 'translateX(120%)';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

function trimPacketList() {
    const mx = parseInt(maxPacketsSelect.value, 10) || 500;
    while (packetList.children.length > mx) {
        packetList.lastChild.remove();
    }
}

// ── Hex Dump ─────────────────────────────────────────────
function formatHexDump(hex) {
    if (!hex) return '(데이터 없음)';
    const bytes = []; for (let i=0; i<hex.length; i+=2) bytes.push(parseInt(hex.substr(i,2),16));
    const lines = [];
    for (let off=0; off<bytes.length; off+=16) {
        const chunk = bytes.slice(off, off+16);
        const oStr = off.toString(16).padStart(4,'0');
        const hArr = chunk.map(b => b.toString(16).padStart(2,'0'));
        const left = hArr.slice(0,8).join(' ').padEnd(23), right = hArr.slice(8).join(' ').padEnd(23);
        const ascii = chunk.map(b => (b>=0x20 && b<0x7f) ? String.fromCharCode(b) : '·').join('');
        lines.push(`<span class="hex-offset">${oStr}</span>  <span class="hex-bytes">${left}  ${right}</span>  <span class="hex-ascii">${ascii}</span>`);
    }
    return lines.join('\n');
}

// ── 패킷 상세 ─────────────────────────────────────────
async function showAnalysis(data) {
    const headerTitle = document.querySelector('.panel-header h3');
    if (headerTitle) headerTitle.textContent = 'Packet Details';
    
    $('hexTitle').style.display = 'flex'; $('hexBox').style.display = 'block';
    
    const dir = data.direction || 'OTHER';
    const dirLabel = dir==='INBOUND' ? '수신 (Inbound)' : dir==='OUTBOUND' ? '송신 (Outbound)' : '기타';
    
    let infoHtml = `<div class="ai-detail-row" style="margin-bottom:15px;">
        <div class="ai-detail-item"><span class="ai-detail-label">패킷 번호</span><span class="ai-detail-value">#${data.no}</span></div>
        <div class="ai-detail-item"><span class="ai-detail-label">방향</span><span class="ai-detail-value">${dirLabel}</span></div>
        <div class="ai-detail-item"><span class="ai-detail-label">출발지</span><span class="ai-detail-value" style="color:var(--accent-blue);">${resolveIp(data.src)}</span></div>
        <div class="ai-detail-item"><span class="ai-detail-label">목적지</span><span class="ai-detail-value" style="color:var(--accent-green);">${resolveIp(data.dst)}</span></div>
        <div class="ai-detail-item"><span class="ai-detail-label">프로토콜 / 크기</span><span class="ai-detail-value">${data.proto} / ${data.len} bytes</span></div>
        <div class="ai-detail-item" style="grid-column: 1 / -1;"><span class="ai-detail-label">요약</span><span class="ai-detail-value" style="font-size:0.85rem;color:var(--text-secondary)">${data.summary||'-'}</span></div>
    </div>`;
    
    let rawStr = data.raw || '';
    let hexHtml = '';
    
    // AI 패킷 분석 버튼
    let aiBtnHtml = `
        <div style="margin-top:20px; margin-bottom: 20px; text-align: center;">
            <button id="aiAnalyzeSingleBtn" class="btn btn-outline" style="width: 100%; height: 44px; border-color: #8b5cf6; color: #8b5cf6;">
                <span class="btn-icon">✨</span> AI로 패킷 분석하기
            </button>
        </div>
        <div id="aiSingleResult" class="markdown-body" style="display:none; background: var(--bg-surface); padding: 20px; border-radius: 8px; border: 1px solid #8b5cf6; margin-bottom: 20px; font-size: 0.95rem; line-height: 1.6; color: var(--text-primary); max-height: 400px; overflow-y: auto;">
        </div>
    `;

    if (rawStr.length > 0) {
        hexHtml = `<div class="hex-panel-title" style="margin-top:20px;margin-bottom:12px;"><span class="hex-icon">📦</span> Raw Packet Dump</div>
                   <div class="hex-box">${formatHexDump(rawStr)}</div>`;
    }
    
    $('hexBox').innerHTML = infoHtml + aiBtnHtml + hexHtml;
    
    // AI 분석 버튼 이벤트 연결
    const aiBtn = $('aiAnalyzeSingleBtn');
    if (aiBtn) {
        aiBtn.addEventListener('click', async () => {
            aiBtn.innerHTML = '<span class="btn-icon">⏳</span> AI가 패킷을 분석 중입니다...';
            aiBtn.disabled = true;
            try {
                const res = await fetch('/api/ai-analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ packets: [data] })
                });
                const r = await res.json();
                const resBox = $('aiSingleResult');
                resBox.style.display = 'block';
                if (r.success) {
                    resBox.innerHTML = marked.parse(r.result);
                } else {
                    resBox.innerHTML = `<span style="color:var(--accent-red)">오류: ${r.error}</span>`;
                }
            } catch (e) {
                $('aiSingleResult').style.display = 'block';
                $('aiSingleResult').innerHTML = `<span style="color:var(--accent-red)">오류: ${e.message}</span>`;
            } finally {
                aiBtn.innerHTML = '<span class="btn-icon">✨</span> AI로 패킷 분석하기';
                aiBtn.disabled = false;
            }
        });
    }
    
    // 분석 내용이 있으면 패널을 연다
    const aiPanel = $('aiPanel');
    const resizer = $('resizer');
    if (aiPanel && aiPanel.classList.contains('collapsed')) {
        aiPanel.classList.remove('collapsed');
        if (resizer) resizer.classList.remove('collapsed');
        if ($('sideToggleIcon')) $('sideToggleIcon').textContent = '▶';
    }
}

// IP 위험도 분석 모달 함수
async function showAiRiskAssess(ip) {
    const btn = $('aiRiskAssessBtn');
    const oldHtml = btn.innerHTML;
    btn.innerHTML = '<span class="btn-icon">⏳</span> 분석 중...';
    btn.disabled = true;
    
    try {
        const res = await fetch('/api/ai-risk-assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        const r = await res.json();
        
        // 분석 결과를 표시하기 위해 우측 패널 재활용
        $('hexTitle').style.display = 'none';
        $('hexBox').style.display = 'block';
        
        let contentHtml = '';
        if (r.success) {
            contentHtml = marked.parse(r.result);
        } else {
            contentHtml = `<span style="color:var(--accent-red)">오류: ${r.error}</span>`;
        }
        
        $('hexBox').innerHTML = `
            <div style="padding: 20px;">
                <h3 style="color: var(--accent-amber); margin-top:0;">🤖 IP 위험도 분석 결과: ${ip}</h3>
                <hr style="border-color: var(--border-color); margin-bottom: 20px;">
                <div class="markdown-body" style="line-height: 1.6; font-size: 0.95rem; color: var(--text-primary);">${contentHtml}</div>
            </div>
        `;
        
        const aiPanel = $('aiPanel');
        const resizer = $('resizer');
        if (aiPanel && aiPanel.classList.contains('collapsed')) {
            aiPanel.classList.remove('collapsed');
            if (resizer) resizer.classList.remove('collapsed');
            if ($('sideToggleIcon')) $('sideToggleIcon').textContent = '▶';
        }
    } catch (e) {
        alert('위험도 분석 중 오류가 발생했습니다: ' + e.message);
    } finally {
        btn.innerHTML = oldHtml;
        btn.disabled = false;
    }
}


// ── 패널 열기/닫기 토글 ───────────────────────────────────
if ($('sideToggleBar')) {
    $('sideToggleBar').addEventListener('click', () => {
        const aiPanel = $('aiPanel');
        const resizer = $('resizer');
        const icon = $('sideToggleIcon');
        if (aiPanel) {
            const isCollapsed = aiPanel.classList.toggle('collapsed');
            if (resizer) resizer.classList.toggle('collapsed', isCollapsed);
            if (icon) {
                icon.textContent = isCollapsed ? '◀' : '▶';
            }
        }
    });
}
if ($('closePanelBtn')) {
    $('closePanelBtn').addEventListener('click', () => {
        const aiPanel = $('aiPanel');
        const resizer = $('resizer');
        if (aiPanel) aiPanel.classList.add('collapsed');
        if (resizer) resizer.classList.add('collapsed');
        if ($('sideToggleIcon')) $('sideToggleIcon').textContent = '◀';
    });
}
