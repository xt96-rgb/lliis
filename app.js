/* ================================================================
   Content Detection Platform — Application Logic
   ================================================================ */

(function () {
  'use strict';

  // ── Storage Keys ───────────────────────────────────────────────
  const STORAGE_RULES = 'content_detection_rules';
  const STORAGE_HISTORY = 'content_detection_history';
  const STORAGE_MODEL_CONFIGS = 'content_detection_llm_configs';
  const STORAGE_PROMPT_TEMPLATES = 'content_detection_prompt_templates';
  const STORAGE_API_KEY_MASK_MAP = 'content_detection_api_key_masks';
  const STORAGE_MODEL_CONFIG_OLD = 'content_detection_llm_config';
  const STORAGE_API_KEY_MASK_OLD = 'content_detection_api_key_masked';
  const STORAGE_BATCH_TASKS = 'content_detection_batch_tasks';

  // ── Default Data ───────────────────────────────────────────────
  const DEFAULT_RULES = [
    { id: 'R001', keyword: '涉政测试', matchType: 'contains', label: '涉政风险', riskLevel: 'high', auditResult: 'violate', enabled: true, remark: '测试规则', createdAt: '', updatedAt: '' },
    { id: 'R002', keyword: '色情测试', matchType: 'contains', label: '色情低俗', riskLevel: 'high', auditResult: 'violate', enabled: true, remark: '测试规则', createdAt: '', updatedAt: '' },
    { id: 'R003', keyword: '辱骂测试', matchType: 'contains', label: '辱骂攻击', riskLevel: 'medium', auditResult: 'suspect', enabled: true, remark: '测试规则', createdAt: '', updatedAt: '' },
    { id: 'R004', keyword: '广告测试', matchType: 'contains', label: '广告引流', riskLevel: 'medium', auditResult: 'suspect', enabled: true, remark: '测试规则', createdAt: '', updatedAt: '' }
  ];

  const DEFAULT_MODEL_CONFIG = {
    config_name: '',
    provider: 'deepseek',
    category: 'multimodal',
    base_url: 'https://api.deepseek.com',
    api_key_masked: '',
    model_name: 'deepseek-chat',
    temperature: 0.2,
    max_tokens: 1200,
    timeout_seconds: 30,
    json_mode: true,
    status: 'enabled'
  };

  const DEFAULT_SYSTEM_PROMPT = [
    '你是一名内容安全审核专家。',
    '',
    '你需要对用户提交的文本内容进行审核。',
    '',
    '请严格识别以下风险类型：',
    '',
    '1. 涉政',
    '2. 色情',
    '3. 谩骂',
    '4. 灌水',
    '5. 广告',
    '6. 违禁',
    '',
    '如果内容不存在风险，则标签返回"正常"。',
    '',
    '请严格按照以下 JSON 格式返回：',
    '',
    '{',
    '  "result": "pass/reject",',
    '  "label": "涉政/色情/谩骂/灌水/广告/违禁/正常",',
    '  "reason": "审核理由"',
    '}',
    '',
    '禁止输出 Markdown。',
    '禁止输出额外解释。',
    '禁止输出 JSON 以外内容。'
  ].join('\n');

  const DEFAULT_USER_PROMPT = [
    '请审核以下文本内容：',
    '',
    '{{content}}'
  ].join('\n');

  const DEFAULT_PROMPT_TEMPLATE = {
    prompt_name: '默认文本审核 Prompt',
    prompt_type: 'text_audit',
    system_prompt: DEFAULT_SYSTEM_PROMPT,
    user_prompt: DEFAULT_USER_PROMPT,
    status: 'enabled',
    remark: '系统默认 Prompt 模板',
    parse_fields: ['result', 'label', 'reason']
  };

  // ── State ──────────────────────────────────────────────────────
  let rules = [];
  let history = [];
  let modelConfigs = [];
  let promptTemplates = [];
  let apiKeysInMemory = {};
  let currentModelConfigId = null;
  let currentPromptId = null;
  let batchTasks = [];
  let activeBatchTimer = null;
  let currentBatchTaskId = null;
  let pendingBatchFileData = null; // parsed Excel data awaiting task creation
  let editingRuleId = null;
  let currentContentType = 'text';

  // ── Helpers ────────────────────────────────────────────────────
  function generateId(prefix) {
    return prefix + Date.now().toString(36).toUpperCase() + Math.random().toString(36).substring(2, 6).toUpperCase();
  }

  function now() {
    return new Date().toISOString();
  }

  function formatTime(isoStr) {
    if (!isoStr) return '-';
    var d = new Date(isoStr);
    var pad = function (n) { return n < 10 ? '0' + n : n; };
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
      ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  function contentTypeLabel(type) {
    var map = { text: '文本', image: '图片', video: '视频' };
    return map[type] || type;
  }

  function auditResultLabel(result) {
    var map = { pass: '通过', suspect: '疑似', violate: '违规' };
    return map[result] || result;
  }

  function riskLevelLabel(level) {
    var map = { none: '无', low: '低危', medium: '中危', high: '高危' };
    return map[level] || level;
  }

  // ── Storage ────────────────────────────────────────────────────
  function loadRules() {
    try {
      var raw = localStorage.getItem(STORAGE_RULES);
      if (raw) { rules = JSON.parse(raw); return; }
    } catch (e) { /* corrupted data */ }
    var nowStr = now();
    rules = DEFAULT_RULES.map(function (r) { r.createdAt = nowStr; r.updatedAt = nowStr; return r; });
    saveRules();
  }

  function saveRules() {
    localStorage.setItem(STORAGE_RULES, JSON.stringify(rules));
  }

  function loadHistory() {
    try {
      var raw = localStorage.getItem(STORAGE_HISTORY);
      if (raw) { history = JSON.parse(raw); }
    } catch (e) { history = []; }
  }

  function saveHistory() {
    localStorage.setItem(STORAGE_HISTORY, JSON.stringify(history));
  }

  function loadModelConfigs() {
    try {
      var raw = localStorage.getItem(STORAGE_MODEL_CONFIGS);
      if (raw) {
        modelConfigs = JSON.parse(raw);
      }
    } catch (e) { modelConfigs = []; }

    // Data migration: old single config → new array format
    if (modelConfigs.length === 0) {
      try {
        var oldRaw = localStorage.getItem(STORAGE_MODEL_CONFIG_OLD);
        if (oldRaw) {
          var old = JSON.parse(oldRaw);
          if (old.config_name || old.base_url) {
            var migrated = {
              id: generateId('MC'),
              config_name: old.config_name || '',
              provider: old.provider || 'deepseek',
              base_url: old.base_url || 'https://api.deepseek.com',
              api_key_masked: old.api_key_masked || '',
              model_name: old.model_name || 'deepseek-chat',
              temperature: old.temperature || 0.2,
              max_tokens: old.max_tokens || 1200,
              timeout_seconds: old.timeout_seconds || 30,
              json_mode: old.json_mode !== undefined ? old.json_mode : true,
              status: old.status === 'enabled' ? 'enabled' : 'disabled',
              category: old.category || 'multimodal',
              updatedAt: now()
            };
            modelConfigs.push(migrated);
            // Migrate masked key
            var oldMasked = localStorage.getItem(STORAGE_API_KEY_MASK_OLD);
            if (oldMasked) {
              var maskMap = {};
              maskMap[migrated.id] = oldMasked;
              localStorage.setItem(STORAGE_API_KEY_MASK_MAP, JSON.stringify(maskMap));
              migrated.api_key_masked = oldMasked;
            }
            saveModelConfigs();
            // Clean up old keys
            localStorage.removeItem(STORAGE_MODEL_CONFIG_OLD);
            localStorage.removeItem(STORAGE_API_KEY_MASK_OLD);
          }
        }
      } catch (e) { /* migration failed, start fresh */ }
    }

    // Load masked API keys
    try {
      var maskRaw = localStorage.getItem(STORAGE_API_KEY_MASK_MAP);
      if (maskRaw) {
        var maskMap = JSON.parse(maskRaw);
        modelConfigs.forEach(function (mc) {
          if (maskMap[mc.id]) mc.api_key_masked = maskMap[mc.id];
        });
      }
    } catch (e) { /* ignore */ }
  }

  function saveModelConfigs() {
    var toSave = modelConfigs.map(function (mc) {
      var copy = Object.assign({}, mc);
      delete copy.api_key;
      return copy;
    });
    localStorage.setItem(STORAGE_MODEL_CONFIGS, JSON.stringify(toSave));
    // Save masked key map
    var maskMap = {};
    modelConfigs.forEach(function (mc) {
      if (mc.api_key_masked) maskMap[mc.id] = mc.api_key_masked;
    });
    if (Object.keys(maskMap).length > 0) {
      localStorage.setItem(STORAGE_API_KEY_MASK_MAP, JSON.stringify(maskMap));
    }
  }

  function loadPromptTemplates() {
    try {
      var raw = localStorage.getItem(STORAGE_PROMPT_TEMPLATES);
      if (raw) {
        promptTemplates = JSON.parse(raw);
        // Migrate prompts missing parse_fields
        var migrated = false;
        promptTemplates.forEach(function (p) {
          if (!p.parse_fields || !Array.isArray(p.parse_fields)) {
            p.parse_fields = ['result', 'label', 'reason'];
            migrated = true;
          }
        });
        if (migrated) savePromptTemplates();
        return;
      }
    } catch (e) { promptTemplates = []; }
    // Seed default prompt template on first load
    var tmpl = Object.assign({}, DEFAULT_PROMPT_TEMPLATE);
    tmpl.id = generateId('PM');
    tmpl.createdAt = now();
    tmpl.updatedAt = now();
    promptTemplates = [tmpl];
    savePromptTemplates();
  }

  function savePromptTemplates() {
    localStorage.setItem(STORAGE_PROMPT_TEMPLATES, JSON.stringify(promptTemplates));
  }

  function loadBatchTasks() {
    try {
      var raw = localStorage.getItem(STORAGE_BATCH_TASKS);
      if (raw) { batchTasks = JSON.parse(raw); } else { batchTasks = []; return; }
    } catch (e) { batchTasks = []; return; }
    // Clean up tasks older than 7 days
    var cutoff = Date.now() - 7 * 24 * 3600 * 1000;
    batchTasks = batchTasks.filter(function (t) {
      return new Date(t.created_at).getTime() > cutoff;
    });
    saveBatchTasks();
  }

  function saveBatchTasks() {
    localStorage.setItem(STORAGE_BATCH_TASKS, JSON.stringify(batchTasks));
  }

  function getBatchTaskById(id) {
    return batchTasks.filter(function (t) { return t.task_id === id; })[0];
  }

  function batchTaskStatusLabel(status) {
    var map = {
      pending: '待执行', running: '执行中', paused: '已暂停',
      cancelled: '已取消', completed: '已完成',
      partial_failed: '部分失败', failed: '执行失败'
    };
    return map[status] || status;
  }

  function maskApiKey(key) {
    if (!key || key.length < 8) return key || '';
    var prefix = key.substring(0, 3);
    var suffix = key.substring(key.length - 4);
    var masked = '';
    for (var i = 0; i < Math.min(key.length - 7, 15); i++) { masked += '*'; }
    return prefix + '-' + masked + suffix;
  }

  // ── Dashboard ──────────────────────────────────────────────────
  function updateDashboard() {
    var enabledRules = rules.filter(function (r) { return r.enabled; });
    document.getElementById('statTotalRules').textContent = enabledRules.length;

    var todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    var todayStr = todayStart.toISOString();
    var todayDetections = history.filter(function (h) { return h.completedAt >= todayStr; });
    document.getElementById('statTodayDetections').textContent = todayDetections.length;

    var violations = history.filter(function (h) { return h.auditResult === 'violate'; });
    document.getElementById('statViolations').textContent = violations.length;

    if (history.length > 0) {
      var passed = history.filter(function (h) { return h.auditResult === 'pass'; });
      var rate = Math.round((passed.length / history.length) * 100);
      document.getElementById('statPassRate').textContent = rate + '%';
    } else {
      document.getElementById('statPassRate').textContent = '-';
    }
  }

  // ── Menu Navigation ────────────────────────────────────────────
  function switchMenu(menuName) {
    document.querySelectorAll('.menu-sub-item').forEach(function (m) { m.classList.remove('active'); });
    var subTarget = document.querySelector('.menu-sub-item[data-menu="' + menuName + '"]');
    if (subTarget) subTarget.classList.add('active');

    document.querySelectorAll('.menu-item').forEach(function (m) { m.classList.remove('active'); });

    // Annotation sub-pages: all map to the unified annotation tab
    var annoModes = ['annotation-image-multi', 'annotation-image-eval', 'annotation-text-multi'];
    var isAnnoPage = annoModes.indexOf(menuName) !== -1;

    // Edit/detail sub-pages: highlight the parent menu item
    var isEditPage = menuName === 'model-config-edit' || menuName === 'prompt-config-edit' || menuName === 'batch-test-detail';
    if (subTarget || isEditPage || isAnnoPage) {
      var parentMenu = isAnnoPage ? 'annotation' : 'model';
      var parentItem = document.querySelector('.menu-parent[data-menu="' + parentMenu + '"]');
      if (parentItem) parentItem.classList.add('active');
      // Highlight the list sub-item matching the edit/detail page
      var listName = menuName;
      if (menuName === 'model-config-edit') listName = 'model-config';
      else if (menuName === 'prompt-config-edit') listName = 'prompt-config';
      else if (menuName === 'batch-test-detail') listName = 'batch-test';
      if (isEditPage) {
        var listItem = document.querySelector('.menu-sub-item[data-menu="' + listName + '"]');
        if (listItem) listItem.classList.add('active');
      }
    } else {
      var topTarget = document.querySelector('.menu-item[data-menu="' + menuName + '"]');
      if (topTarget) topTarget.classList.add('active');
    }

    document.querySelectorAll('.tab-content').forEach(function (c) { c.classList.remove('active'); });

    // Annotation sub-items all go to the unified annotation tab
    var tabId = isAnnoPage ? 'tab-annotation' : 'tab-' + menuName;
    var tabEl = document.getElementById(tabId);
    if (tabEl) tabEl.classList.add('active');

    if (isAnnoPage) {
      var modeMap = {
        'annotation-image-multi': 'imageMulti',
        'annotation-image-eval': 'imageEval',
        'annotation-text-multi': 'textMulti'
      };
      switchAnnoMode(modeMap[menuName]);
    }

    if (menuName === 'single-test') {
      renderSingleTestSelects();
      document.getElementById('stTestResult').style.display = 'none';
      document.getElementById('stTestStatusText').textContent = '';
      document.querySelectorAll('.ct-tab').forEach(function (t) { t.classList.remove('active'); });
      var textTab = document.querySelector('.ct-tab[data-ct="text"]');
      if (textTab) textTab.classList.add('active');
      document.querySelectorAll('.ct-panel').forEach(function (p) { p.classList.remove('active'); });
      var textPanel = document.getElementById('ct-panel-text');
      if (textPanel) textPanel.classList.add('active');
    }
    if (menuName === 'batch-test') {
      renderBatchCreateSelects();
      updateBatchUploadSection(document.getElementById('btPromptTemplate').value);
      updateBatchTemplateHint();
      renderBatchProgress();
      pendingBatchFileData = null;
      document.getElementById('btFileInfo').style.display = 'none';
      document.getElementById('btParsePreview').style.display = 'none';
      document.getElementById('btFileInput').value = '';
      document.getElementById('btCreateStatus').textContent = '';
      // Reset to create tab
      document.querySelectorAll('#btSubTabs .ct-tab').forEach(function (t) { t.classList.remove('active'); });
      var createTab = document.querySelector('#btSubTabs .ct-tab[data-bt-tab="create"]');
      if (createTab) createTab.classList.add('active');
      document.querySelectorAll('.bt-panel').forEach(function (p) { p.classList.remove('active'); });
      var createPanel = document.getElementById('bt-panel-create');
      if (createPanel) createPanel.classList.add('active');
    }
  }

  function backToBatchList() {
    currentBatchTaskId = null;
    switchMenu('batch-test');
    renderBatchTaskList();
    renderBatchProgress();
  }

  // ── Content Type Switching ─────────────────────────────────────
  function setContentType(type) {
    currentContentType = type;
    var buttons = document.querySelectorAll('.ct-btn');
    buttons.forEach(function (btn) {
      btn.classList.toggle('active', btn.dataset.ct === type);
    });
    updateContentTypeUI();
  }

  function updateContentTypeUI() {
    var type = currentContentType;
    document.getElementById('groupText').style.display = type === 'text' ? 'block' : 'none';
    document.getElementById('groupImage').style.display = type === 'image' ? 'block' : 'none';
    document.getElementById('groupVideo').style.display = type === 'video' ? 'block' : 'none';

    document.getElementById('textContent').required = (type === 'text');
    document.getElementById('imageFile').required = (type === 'image');
    document.getElementById('videoFile').required = (type === 'video');

    document.getElementById('resultCard').style.display = 'none';
  }

  // ── File Validation ────────────────────────────────────────────
  function validateFile(file, contentType) {
    if (!file) return null;
    if (contentType === 'image') {
      var allowedExts = ['jpg', 'jpeg', 'png', 'webp'];
      var ext = file.name.split('.').pop().toLowerCase();
      if (allowedExts.indexOf(ext) === -1) {
        return '当前文件格式不支持，仅支持 JPG / JPEG / PNG / WebP';
      }
      if (file.size > 10 * 1024 * 1024) {
        return '文件大小超过限制（最大 10MB）';
      }
    }
    if (contentType === 'video') {
      var allowedExts = ['mp4', 'mov', 'avi', 'mkv'];
      var ext = file.name.split('.').pop().toLowerCase();
      if (allowedExts.indexOf(ext) === -1) {
        return '当前文件格式不支持，仅支持 MP4 / MOV / AVI / MKV';
      }
      if (file.size > 100 * 1024 * 1024) {
        return '文件大小超过限制（最大 100MB）';
      }
    }
    return null;
  }

  // ── Validation ─────────────────────────────────────────────────
  function validateInput(formData) {
    var errors = [];
    if (formData.contentType === 'text') {
      if (!formData.text || !formData.text.trim()) {
        errors.push('请输入正文内容');
      }
    } else if (formData.contentType === 'image') {
      if (!formData.file) {
        errors.push('请上传图片');
      }
    } else if (formData.contentType === 'video') {
      if (!formData.file) {
        errors.push('请上传视频');
      }
    }
    return errors;
  }

  // ── Detection Algorithm ────────────────────────────────────────
  function generateHitSnippet(content, keyword) {
    var idx = content.indexOf(keyword);
    if (idx === -1) return content.substring(0, 40);
    var start = Math.max(0, idx - 20);
    var end = Math.min(content.length, idx + keyword.length + 20);
    return content.substring(start, end);
  }

  function matchKeywords(content, enabledRules) {
    return enabledRules.filter(function (rule) {
      return content.value.indexOf(rule.keyword) !== -1;
    }).map(function (rule) {
      return {
        field: content.field,
        keyword: rule.keyword,
        label: rule.label,
        riskLevel: rule.riskLevel,
        auditResult: rule.auditResult,
        snippet: generateHitSnippet(content.value, rule.keyword)
      };
    });
  }

  function calculateFinalResult(hitDetails) {
    if (!hitDetails.length) {
      return {
        auditResult: 'pass',
        riskLevel: 'none',
        labels: [],
        hitDetails: []
      };
    }

    var resultPriority = { pass: 0, suspect: 1, violate: 2 };
    var riskPriority = { none: 0, low: 1, medium: 2, high: 3 };

    var finalAuditResult = hitDetails.reduce(function (max, item) {
      return resultPriority[item.auditResult] > resultPriority[max] ? item.auditResult : max;
    }, 'pass');

    var finalRiskLevel = hitDetails.reduce(function (max, item) {
      return riskPriority[item.riskLevel] > riskPriority[max] ? item.riskLevel : max;
    }, 'none');

    var labels = [];
    hitDetails.forEach(function (item) {
      if (labels.indexOf(item.label) === -1) { labels.push(item.label); }
    });

    return {
      auditResult: finalAuditResult,
      riskLevel: finalRiskLevel,
      labels: labels,
      hitDetails: hitDetails
    };
  }

  function detectContent(formData) {
    var enabledRules = rules.filter(function (r) { return r.enabled; });

    var fieldsToCheck = [];
    if (formData.title) {
      fieldsToCheck.push({ field: 'title', value: formData.title });
    }

    if (formData.contentType === 'text') {
      fieldsToCheck.push({ field: 'text', value: formData.text });
    }

    var allHitDetails = [];
    fieldsToCheck.forEach(function (fieldItem) {
      var hits = matchKeywords(fieldItem, enabledRules);
      allHitDetails = allHitDetails.concat(hits);
    });

    return calculateFinalResult(allHitDetails);
  }

  // ── Render Detection Result ────────────────────────────────────
  function renderDetectionResult(detectionResult, formData) {
    var badgeClass = 'badge-' + detectionResult.auditResult;
    var riskClass = 'badge-' + detectionResult.riskLevel;

    var modeLabel = '敏感词匹配';

    var html = '';
    html += '<div class="result-summary">';
    html += '  <div class="result-item"><div class="result-item-label">审核结果</div>';
    html += '    <div class="result-item-value"><span class="badge ' + badgeClass + '">' + auditResultLabel(detectionResult.auditResult) + '</span></div></div>';
    html += '  <div class="result-item"><div class="result-item-label">风险等级</div>';
    html += '    <div class="result-item-value"><span class="badge ' + riskClass + '">' + riskLevelLabel(detectionResult.riskLevel) + '</span></div></div>';
    html += '  <div class="result-item"><div class="result-item-label">检测方式</div>';
    html += '    <div class="result-item-value"><span class="badge badge-info">' + modeLabel + '</span></div></div>';
    html += '  <div class="result-item"><div class="result-item-label">命中数量</div>';
    html += '    <div class="result-item-value">' + detectionResult.hitDetails.length + '</div></div>';
    html += '</div>';

    if (detectionResult.labels.length > 0) {
      html += '<div style="margin-bottom:12px;"><strong>审核标签：</strong> ';
      html += detectionResult.labels.map(function (l) { return '<span class="badge badge-warning" style="margin-right:6px;">' + l + '</span>'; }).join('');
      html += '</div>';
    }

    if (detectionResult.hitDetails.length > 0) {
      html += '<div class="hit-table"><table class="table"><thead><tr>';
      html += '<th>命中位置</th><th>命中关键词</th><th>标签</th><th>风险等级</th>';
      html += '<th>审核结果</th><th>命中片段</th></tr></thead><tbody>';

      detectionResult.hitDetails.forEach(function (hit) {
        var fieldLabel = hit.field === 'title' ? '标题' : '正文';
        var snippetHtml = hit.snippet.replace(
          hit.keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
          '<span class="hit-keyword-highlight">' + hit.keyword + '</span>'
        );
        html += '<tr>';
        html += '<td>' + fieldLabel + '</td>';
        html += '<td><strong>' + hit.keyword + '</strong></td>';
        html += '<td>' + hit.label + '</td>';
        html += '<td><span class="badge badge-' + hit.riskLevel + '">' + riskLevelLabel(hit.riskLevel) + '</span></td>';
        html += '<td><span class="badge badge-' + hit.auditResult + '">' + auditResultLabel(hit.auditResult) + '</span></td>';
        html += '<td><span class="hit-snippet">' + snippetHtml + '</span></td>';
        html += '</tr>';
      });

      html += '</tbody></table></div>';
    } else {
      html += '<p style="text-align:center;color:#909399;padding:20px;">未命中任何规则，内容通过审核</p>';
    }

    document.getElementById('resultContent').innerHTML = html;
    document.getElementById('resultCard').style.display = 'block';
  }

  // ── Handle Detection Submit ────────────────────────────────────
  function handleDetectSubmit(e) {
    e.preventDefault();

    var contentType = currentContentType;

    var formData = {
      contentType: contentType,
      title: document.getElementById('title').value.trim()
    };

    if (contentType === 'text') {
      formData.text = document.getElementById('textContent').value.trim();
    }

    var file = null;
    if (contentType === 'image') {
      file = document.getElementById('imageFile').files[0];
    } else if (contentType === 'video') {
      file = document.getElementById('videoFile').files[0];
    }
    formData.file = file;
    formData.fileName = file ? file.name : '';

    // Validate file
    if (file) {
      var fileError = validateFile(file, contentType);
      if (fileError) {
        alert(fileError);
        return;
      }
    }

    // Validate input
    var errors = validateInput(formData);
    if (errors.length > 0) {
      alert(errors.join('\n'));
      return;
    }

    // Run detection
    var detectionResult = detectContent(formData);

    var record = {
      auditId: generateId('AUD'),
      contentType: formData.contentType,
      title: formData.title,
      text: formData.text || '',
      fileName: formData.fileName,
      auditResult: detectionResult.auditResult,
      riskLevel: detectionResult.riskLevel,
      labels: detectionResult.labels,
      detectMode: 'keyword',
      hitDetails: detectionResult.hitDetails,
      createdAt: now(),
      completedAt: now()
    };

    // Save to history
    history.unshift(record);
    saveHistory();

    // Render result
    renderDetectionResult(detectionResult, formData);

    // Update UI
    updateDashboard();
    renderHistoryTable();
  }

  // ── Rule Table Rendering ───────────────────────────────────────
  function renderRuleTable() {
    var searchTerm = (document.getElementById('ruleSearch').value || '').toLowerCase();
    var filterLabel = document.getElementById('filterLabel').value;
    var filterRisk = document.getElementById('filterRiskLevel').value;

    var filtered = rules.filter(function (rule) {
      var matchSearch = true;
      if (searchTerm) {
        matchSearch = rule.keyword.toLowerCase().indexOf(searchTerm) !== -1 ||
                      rule.label.toLowerCase().indexOf(searchTerm) !== -1 ||
                      (rule.remark || '').toLowerCase().indexOf(searchTerm) !== -1;
      }
      var matchLabel = !filterLabel || rule.label === filterLabel;
      var matchRisk = !filterRisk || rule.riskLevel === filterRisk;
      return matchSearch && matchLabel && matchRisk;
    });

    // Sort by updatedAt descending
    filtered.sort(function (a, b) {
      return (b.updatedAt || '').localeCompare(a.updatedAt || '');
    });

    var tbody = document.getElementById('ruleTableBody');
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="table-empty">暂无匹配的规则</td></tr>';
    } else {
      tbody.innerHTML = filtered.map(function (rule) {
        return '<tr>' +
          '<td><strong>' + escHtml(rule.keyword) + '</strong></td>' +
          '<td>' + escHtml(rule.label) + '</td>' +
          '<td><span class="badge badge-' + rule.riskLevel + '">' + riskLevelLabel(rule.riskLevel) + '</span></td>' +
          '<td><span class="badge badge-' + rule.auditResult + '">' + auditResultLabel(rule.auditResult) + '</span></td>' +
          '<td><button class="btn-toggle ' + (rule.enabled ? 'on' : 'off') + '" data-toggle-rule="' + rule.id + '"></button></td>' +
          '<td>' + escHtml(rule.remark || '-') + '</td>' +
          '<td>' + formatTime(rule.updatedAt) + '</td>' +
          '<td>' +
            '<button class="btn-link" data-edit-rule="' + rule.id + '">编辑</button> ' +
            '<button class="btn-link" data-delete-rule="' + rule.id + '" style="color:#f56c6c;">删除</button>' +
          '</td>' +
        '</tr>';
      }).join('');
    }

    document.getElementById('ruleCount').textContent = '共 ' + filtered.length + ' 条规则';

    // Update label filter options
    var allLabels = [];
    rules.forEach(function (r) {
      if (allLabels.indexOf(r.label) === -1) { allLabels.push(r.label); }
    });
    var labelSelect = document.getElementById('filterLabel');
    var currentVal = labelSelect.value;
    labelSelect.innerHTML = '<option value="">全部标签</option>' +
      allLabels.map(function (l) {
        return '<option value="' + escHtml(l) + '">' + escHtml(l) + '</option>';
      }).join('');
    labelSelect.value = currentVal;
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Rule CRUD ──────────────────────────────────────────────────
  function openRuleModal(ruleId) {
    var modal = document.getElementById('ruleModal');
    var form = document.getElementById('ruleForm');
    form.reset();

    if (ruleId) {
      // Edit mode
      var rule = rules.find(function (r) { return r.id === ruleId; });
      if (!rule) return;
      editingRuleId = ruleId;
      document.getElementById('ruleModalTitle').textContent = '编辑关键词';
      document.getElementById('ruleId').value = rule.id;
      document.getElementById('ruleKeyword').value = rule.keyword;
      document.getElementById('ruleLabel').value = rule.label;
      document.getElementById('ruleRiskLevel').value = rule.riskLevel;
      document.getElementById('ruleAuditResult').value = rule.auditResult;
      document.getElementById('ruleRemark').value = rule.remark || '';
    } else {
      // Add mode
      editingRuleId = null;
      document.getElementById('ruleModalTitle').textContent = '新增关键词';
      document.getElementById('ruleId').value = '';
      document.getElementById('ruleRiskLevel').value = 'medium';
      document.getElementById('ruleAuditResult').value = 'suspect';
    }

    modal.style.display = 'flex';
  }

  function closeRuleModal() {
    document.getElementById('ruleModal').style.display = 'none';
    editingRuleId = null;
  }

  function handleRuleFormSubmit(e) {
    e.preventDefault();
    var keyword = document.getElementById('ruleKeyword').value.trim();
    var label = document.getElementById('ruleLabel').value.trim();
    var riskLevel = document.getElementById('ruleRiskLevel').value;
    var auditResult = document.getElementById('ruleAuditResult').value;
    var remark = document.getElementById('ruleRemark').value.trim();

    if (!keyword) { alert('请填写关键词'); return; }
    if (!label) { alert('请填写审核标签'); return; }

    var nowStr = now();
    if (editingRuleId) {
      var rule = rules.find(function (r) { return r.id === editingRuleId; });
      if (rule) {
        rule.keyword = keyword;
        rule.label = label;
        rule.riskLevel = riskLevel;
        rule.auditResult = auditResult;
        rule.remark = remark;
        rule.updatedAt = nowStr;
      }
    } else {
      rules.push({
        id: generateId('R'),
        keyword: keyword,
        matchType: 'contains',
        label: label,
        riskLevel: riskLevel,
        auditResult: auditResult,
        enabled: true,
        remark: remark,
        createdAt: nowStr,
        updatedAt: nowStr
      });
    }

    saveRules();
    closeRuleModal();
    renderRuleTable();
    updateDashboard();
  }

  function deleteRule(ruleId) {
    if (!confirm('确定要删除这条规则吗？')) return;
    rules = rules.filter(function (r) { return r.id !== ruleId; });
    saveRules();
    renderRuleTable();
    updateDashboard();
  }

  function toggleRule(ruleId) {
    var rule = rules.find(function (r) { return r.id === ruleId; });
    if (rule) {
      rule.enabled = !rule.enabled;
      rule.updatedAt = now();
      saveRules();
      renderRuleTable();
      updateDashboard();
    }
  }

  // ── History Table ──────────────────────────────────────────────
  function renderHistoryTable() {
    var tbody = document.getElementById('historyTableBody');
    if (history.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="table-empty">暂无检测记录</td></tr>';
    } else {
      tbody.innerHTML = history.map(function (record) {
        var labelsHtml = record.labels.length > 0
          ? record.labels.map(function (l) { return '<span class="badge badge-warning" style="margin-right:4px;">' + escHtml(l) + '</span>'; }).join('')
          : '-';
        return '<tr>' +
          '<td><code>' + record.auditId + '</code></td>' +
          '<td>' + contentTypeLabel(record.contentType) + '</td>' +
          '<td title="' + escHtml(record.title) + '">' + escHtml(truncate(record.title, 20)) + '</td>' +
          '<td><span class="badge badge-' + record.auditResult + '">' + auditResultLabel(record.auditResult) + '</span></td>' +
          '<td><span class="badge badge-' + record.riskLevel + '">' + riskLevelLabel(record.riskLevel) + '</span></td>' +
          '<td>' + labelsHtml + '</td>' +
          '<td>' + record.detectMode + '</td>' +
          '<td>' + formatTime(record.completedAt) + '</td>' +
          '<td><button class="btn-link" data-view-history="' + record.auditId + '">查看详情</button></td>' +
        '</tr>';
      }).join('');
    }
    document.getElementById('historyCount').textContent = '共 ' + history.length + ' 条记录';
  }

  function truncate(str, len) {
    if (str.length <= len) return str;
    return str.substring(0, len) + '...';
  }

  // ── History Detail ─────────────────────────────────────────────
  function viewHistoryDetail(auditId) {
    var record = history.find(function (h) { return h.auditId === auditId; });
    if (!record) return;

    var html = '';
    html += '<div class="detail-section"><h4>基本信息</h4>';
    html += '<table class="table"><tbody>';
    html += '<tr><td style="width:120px;color:#909399;">检测ID</td><td><code>' + record.auditId + '</code></td></tr>';
    html += '<tr><td>内容类型</td><td>' + contentTypeLabel(record.contentType) + '</td></tr>';
    html += '<tr><td>标题</td><td>' + escHtml(record.title) + '</td></tr>';
    if (record.text) {
      html += '<tr><td>正文内容</td><td style="max-width:300px;word-break:break-all;">' + escHtml(record.text) + '</td></tr>';
    }
    if (record.fileName) {
      html += '<tr><td>文件名</td><td>' + escHtml(record.fileName) + '</td></tr>';
    }
    html += '<tr><td>审核结果</td><td><span class="badge badge-' + record.auditResult + '">' + auditResultLabel(record.auditResult) + '</span></td></tr>';
    html += '<tr><td>风险等级</td><td><span class="badge badge-' + record.riskLevel + '">' + riskLevelLabel(record.riskLevel) + '</span></td></tr>';
    html += '<tr><td>审核标签</td><td>' + (record.labels.length > 0 ? record.labels.join('，') : '无') + '</td></tr>';
    html += '<tr><td>检测方式</td><td>' + record.detectMode + '</td></tr>';
    html += '<tr><td>检测时间</td><td>' + formatTime(record.completedAt) + '</td></tr>';
    html += '</tbody></table></div>';

    if (record.hitDetails.length > 0) {
      html += '<div class="detail-section"><h4>命中详情</h4>';
      html += '<table class="table"><thead><tr><th>位置</th><th>关键词</th><th>标签</th><th>风险等级</th><th>审核结果</th></tr></thead><tbody>';
      record.hitDetails.forEach(function (hit) {
        html += '<tr>';
        html += '<td>' + (hit.field === 'title' ? '标题' : '正文') + '</td>';
        html += '<td><strong>' + escHtml(hit.keyword) + '</strong></td>';
        html += '<td>' + escHtml(hit.label) + '</td>';
        html += '<td><span class="badge badge-' + hit.riskLevel + '">' + riskLevelLabel(hit.riskLevel) + '</span></td>';
        html += '<td><span class="badge badge-' + hit.auditResult + '">' + auditResultLabel(hit.auditResult) + '</span></td>';
        html += '</tr>';
      });
      html += '</tbody></table></div>';
    }

    document.getElementById('historyDetailContent').innerHTML = html;
    document.getElementById('historyModal').style.display = 'flex';
  }

  function closeHistoryModal() {
    document.getElementById('historyModal').style.display = 'none';
  }

  // ── Model Config CRUD ──────────────────────────────────────────
  function getModelConfigById(id) {
    return modelConfigs.find(function (mc) { return mc.id === id; });
  }

  function renderModelConfigList() {
    var filter = document.getElementById('filterModelStatus').value;
    var filtered = modelConfigs.filter(function (mc) {
      return !filter || mc.status === filter;
    });
    filtered.sort(function (a, b) {
      return (b.updatedAt || '').localeCompare(a.updatedAt || '');
    });

    var tbody = document.getElementById('modelConfigTableBody');
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="table-empty">暂无模型配置，请点击"新建配置"</td></tr>';
    } else {
      tbody.innerHTML = filtered.map(function (mc) {
        var categoryLabel = mc.category === 'unimodal' ? '单模态' : '多模态';
        return '<tr>' +
          '<td><strong>' + escHtml(mc.config_name) + '</strong></td>' +
          '<td>' + (mc.provider === 'deepseek' ? 'DeepSeek' : escHtml(mc.provider)) + '</td>' +
          '<td>' + categoryLabel + '</td>' +
          '<td>' + escHtml(mc.model_name) + '</td>' +
          '<td><label class="switch"><input type="checkbox" class="mc-status-toggle" data-toggle-model="' + mc.id + '"' + (mc.status === 'enabled' ? ' checked' : '') + '><span class="switch-slider"></span></label></td>' +
          '<td>' + formatTime(mc.updatedAt) + '</td>' +
          '<td>' +
            '<button class="btn-link" data-edit-model="' + mc.id + '">编辑</button> ' +
            '<button class="btn-link" data-delete-model="' + mc.id + '" style="color:#f56c6c;">删除</button>' +
          '</td>' +
        '</tr>';
      }).join('');
    }

    // Also update dropdowns on other active tabs
    if (document.getElementById('tab-single-test').classList.contains('active')) {
      renderSingleTestSelects();
    }
    if (document.getElementById('tab-batch-test').classList.contains('active')) {
      renderBatchCreateSelects();
    }
  }

  function openModelConfigEdit(id) {
    var form = document.getElementById('modelConfigForm');
    form.reset();
    document.getElementById('mcmId').value = '';

    if (id) {
      currentModelConfigId = id;
      var mc = getModelConfigById(id);
      if (!mc) return;
      document.getElementById('modelConfigEditTitle').textContent = '编辑模型配置';
      document.getElementById('mcmId').value = mc.id;
      document.getElementById('mcmConfigName').value = mc.config_name || '';
      document.getElementById('mcmCategory').value = mc.category || 'multimodal';
      document.getElementById('mcmBaseUrl').value = mc.base_url || 'https://api.deepseek.com';
      document.getElementById('mcmModelName').value = mc.model_name || 'deepseek-chat';
      document.getElementById('mcmTemperature').value = mc.temperature;
      document.getElementById('mcmMaxTokens').value = mc.max_tokens;
      document.getElementById('mcmTimeout').value = mc.timeout_seconds;

      if (mc.api_key_masked) {
        document.getElementById('mcmApiKey').value = mc.api_key_masked;
        document.getElementById('mcmApiKeyHint').textContent = 'API Key 已保存（脱敏展示）';
      } else {
        document.getElementById('mcmApiKey').value = '';
        document.getElementById('mcmApiKeyHint').textContent = 'API Key 保存后仅展示脱敏信息';
      }
    } else {
      currentModelConfigId = null;
      document.getElementById('modelConfigEditTitle').textContent = '新建模型配置';
      document.getElementById('mcmCategory').value = 'multimodal';
      document.getElementById('mcmBaseUrl').value = 'https://api.deepseek.com';
      document.getElementById('mcmModelName').value = 'deepseek-chat';
      document.getElementById('mcmTemperature').value = 0.2;
      document.getElementById('mcmMaxTokens').value = 1200;
      document.getElementById('mcmTimeout').value = 30;
      document.getElementById('mcmApiKey').value = '';
      document.getElementById('mcmApiKeyHint').textContent = 'API Key 保存后仅展示脱敏信息';
    }

    switchMenu('model-config-edit');
  }

  function backToModelConfigList() {
    currentModelConfigId = null;
    switchMenu('model-config');
    renderModelConfigList();
  }

  function handleSaveModelConfig(e) {
    e.preventDefault();
    var configName = (document.getElementById('mcmConfigName').value || '').trim();
    var category = document.getElementById('mcmCategory').value;
    var baseUrl = (document.getElementById('mcmBaseUrl').value || '').trim();
    var modelName = (document.getElementById('mcmModelName').value || '').trim();
    var temperature = parseFloat(document.getElementById('mcmTemperature').value);
    var maxTokens = parseInt(document.getElementById('mcmMaxTokens').value, 10);
    var timeout = parseInt(document.getElementById('mcmTimeout').value, 10);

    var errors = [];
    if (!configName) errors.push('配置名称不能为空');
    else if (configName.length < 2 || configName.length > 50) errors.push('配置名称长度必须在 2-50 个字符之间');
    if (!baseUrl) errors.push('API Base URL 不能为空');
    // Check API Key: either in memory for this config or already masked
    var mcId = document.getElementById('mcmId').value;
    var existing = mcId ? getModelConfigById(mcId) : null;
    if (!apiKeysInMemory[mcId || 'new'] && !(existing && existing.api_key_masked)) {
      errors.push('API Key 不能为空，请先输入并保存 API Key');
    }
    if (!modelName) errors.push('模型名称不能为空');
    if (isNaN(temperature) || temperature < 0 || temperature > 1) errors.push('Temperature 必须在 0-1 之间');
    if (isNaN(maxTokens) || maxTokens < 256 || maxTokens > 4096) errors.push('最大输出长度必须在 256-4096 之间');
    if (isNaN(timeout) || timeout < 5 || timeout > 120) errors.push('超时时间必须在 5-120 秒之间');

    if (errors.length > 0) {
      alert('保存失败：\n' + errors.join('\n'));
      return;
    }

    var nowStr = now();
    var keyToUse = mcId || 'new';

    if (mcId) {
      var mc = getModelConfigById(mcId);
      if (mc) {
        mc.config_name = configName;
        mc.category = category;
        mc.base_url = baseUrl;
        mc.model_name = modelName;
        mc.temperature = temperature;
        mc.max_tokens = maxTokens;
        mc.timeout_seconds = timeout;
        mc.json_mode = true;
        mc.updatedAt = nowStr;
        if (apiKeysInMemory[mcId]) {
          mc.api_key_masked = maskApiKey(apiKeysInMemory[mcId]);
        }
      }
    } else {
      var newMc = Object.assign({}, DEFAULT_MODEL_CONFIG, {
        id: generateId('MC'),
        config_name: configName,
        category: category,
        base_url: baseUrl,
        model_name: modelName,
        temperature: temperature,
        max_tokens: maxTokens,
        timeout_seconds: timeout,
        json_mode: true,
        status: 'enabled',
        createdAt: nowStr,
        updatedAt: nowStr
      });
      // Transfer API key from "new" slot to actual ID
      if (apiKeysInMemory['new']) {
        apiKeysInMemory[newMc.id] = apiKeysInMemory['new'];
        delete apiKeysInMemory['new'];
        newMc.api_key_masked = maskApiKey(apiKeysInMemory[newMc.id]);
      }
      modelConfigs.push(newMc);
    }

    saveModelConfigs();
    backToModelConfigList();
    renderModelConfigList();
  }

  function handleDeleteModelConfig(id) {
    var mc = getModelConfigById(id);
    if (!mc) return;
    if (mc.status === 'enabled') {
      alert('已启用配置不允许删除，请先停用配置');
      return;
    }
    if (!confirm('删除后该配置不可恢复，是否确认删除？')) return;
    modelConfigs = modelConfigs.filter(function (m) { return m.id !== id; });
    delete apiKeysInMemory[id];
    saveModelConfigs();
    renderModelConfigList();
  }

  function handleToggleModelConfig(id) {
    var mc = getModelConfigById(id);
    if (!mc) return;
    mc.status = mc.status === 'enabled' ? 'disabled' : 'enabled';
    mc.updatedAt = now();
    saveModelConfigs();
    renderModelConfigList();
  }

  function handleTestConnection(id) {
    var mc = getModelConfigById(id);
    if (!mc) return;

    // Simulate connection test with fixed prompt
    var testBtn = document.querySelector('[data-test-conn="' + id + '"]');
    if (testBtn) { testBtn.disabled = true; testBtn.textContent = '测试中...'; }

    var delay = 800 + Math.random() * 1200;
    setTimeout(function () {
      var success = true;
      var message = '';

      if (Math.random() < 0.05) {
        success = false;
        var failures = ['API Key 无效', '模型名称错误', '请求超时', '网络异常', '服务异常'];
        message = failures[Math.floor(Math.random() * failures.length)];
      }

      mc.test_status = success ? 'success' : 'failed';
      mc.updatedAt = now();
      saveModelConfigs();
      renderModelConfigList();

      if (success) {
        alert('连接测试成功！\n返回: {"ok":true}');
      } else {
        alert('连接测试失败：' + message);
      }

      if (testBtn) { testBtn.disabled = false; testBtn.textContent = '测试'; }
    }, delay);
  }

  // ── Model Config API Key Management ─────────────────────────────
  function handleModelApiKeySave() {
    var keyInput = document.getElementById('mcmApiKey');
    var rawKey = keyInput.value.trim();
    if (!rawKey) { alert('请输入 API Key'); return; }
    if (rawKey.indexOf('***') !== -1) { alert('请输入完整的 API Key，而非脱敏值'); return; }

    var mcId = document.getElementById('mcmId').value || 'new';
    apiKeysInMemory[mcId] = rawKey;
    keyInput.value = maskApiKey(rawKey);
    document.getElementById('mcmApiKeyHint').textContent = 'API Key 已保存（脱敏展示）';
  }

  function handleModelApiKeyDelete() {
    if (!confirm('确定要删除 API Key 吗？')) return;
    var mcId = document.getElementById('mcmId').value || 'new';
    delete apiKeysInMemory[mcId];
    document.getElementById('mcmApiKey').value = '';
    document.getElementById('mcmApiKeyHint').textContent = 'API Key 保存后仅展示脱敏信息';
  }

  function handleModelApiKeyToggle() {
    var keyInput = document.getElementById('mcmApiKey');
    var btn = document.getElementById('btnMcmToggleApiKey');
    var mcId = document.getElementById('mcmId').value || 'new';
    if (keyInput.type === 'password') {
      if (apiKeysInMemory[mcId]) {
        keyInput.type = 'text';
        keyInput.value = apiKeysInMemory[mcId];
        btn.textContent = '隐藏';
      } else {
        alert('完整 API Key 仅在当前会话内存中保存，刷新页面后不可查看');
      }
    } else {
      keyInput.type = 'password';
      var existing = mcId !== 'new' ? getModelConfigById(mcId) : null;
      keyInput.value = (existing && existing.api_key_masked) || '';
      btn.textContent = '显示';
    }
  }

  // ── Prompt Template CRUD ────────────────────────────────────────
  function getPromptById(id) {
    return promptTemplates.find(function (p) { return p.id === id; });
  }

  // ── Parse Fields Helpers ─────────────────────────────────────────
  function getParseFieldNames(source) {
    if (source && source.parse_fields && Array.isArray(source.parse_fields)) {
      return source.parse_fields.slice();
    }
    return ['result', 'label', 'reason'];
  }

  function getCurrentParseFieldNames() {
    var editor = document.getElementById('pfTagEditor');
    if (!editor) return ['result', 'label', 'reason'];
    var tags = editor.querySelectorAll('.pf-tag');
    var names = [];
    tags.forEach(function (tag) {
      var textEl = tag.querySelector('.pf-tag-text');
      if (textEl) names.push((textEl.textContent || '').trim());
    });
    return names;
  }

  function enterTagEditMode(tag) {
    var textEl = tag.querySelector('.pf-tag-text');
    var inputEl = tag.querySelector('.pf-tag-input');
    if (!textEl || !inputEl) return;
    textEl.classList.add('editing');
    inputEl.classList.add('active');
    inputEl.value = textEl.textContent;
    inputEl.focus();
    inputEl.select();
  }

  function exitTagEditMode(tag) {
    var textEl = tag.querySelector('.pf-tag-text');
    var inputEl = tag.querySelector('.pf-tag-input');
    if (!textEl || !inputEl) return;
    var newVal = (inputEl.value || '').trim();
    if (newVal) {
      textEl.textContent = newVal;
    }
    inputEl.value = textEl.textContent;
    inputEl.classList.remove('active');
    textEl.classList.remove('editing');
  }

  function renderParseFieldTags(fields) {
    var editor = document.getElementById('pfTagEditor');
    if (!editor) return;
    editor.innerHTML = '';
    var f = (fields && Array.isArray(fields)) ? fields : [];
    f.forEach(function (name, idx) {
      var tag = document.createElement('span');
      tag.className = 'pf-tag';
      tag.setAttribute('data-pf-index', String(idx));

      var textEl = document.createElement('span');
      textEl.className = 'pf-tag-text';
      textEl.textContent = name;

      var inputEl = document.createElement('input');
      inputEl.className = 'pf-tag-input';
      inputEl.maxLength = 20;

      var removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'pf-tag-remove';
      removeBtn.innerHTML = '&times;';
      removeBtn.title = '删除此字段';
      (function (i) {
        removeBtn.addEventListener('click', function () {
          removeParseFieldTag(i);
        });
      })(idx);

      tag.appendChild(textEl);
      tag.appendChild(inputEl);
      tag.appendChild(removeBtn);
      editor.appendChild(tag);
    });

    var addBtn = document.createElement('button');
    addBtn.type = 'button';
    addBtn.className = 'pf-tag-add';
    addBtn.textContent = '+ 添加字段';
    addBtn.title = '添加新的解析字段';
    addBtn.addEventListener('click', function () {
      addParseFieldTag();
    });
    editor.appendChild(addBtn);
  }

  function addParseFieldTag() {
    var fields = getCurrentParseFieldNames();
    fields.push('');
    renderParseFieldTags(fields);
  }

  function removeParseFieldTag(idx) {
    var fields = getCurrentParseFieldNames();
    fields.splice(idx, 1);
    renderParseFieldTags(fields);
  }

  function renderPromptList() {
    var filter = document.getElementById('filterPromptStatus').value;
    var filtered = promptTemplates.filter(function (p) {
      return !filter || p.status === filter;
    });
    filtered.sort(function (a, b) {
      return (b.updatedAt || '').localeCompare(a.updatedAt || '');
    });

    var tbody = document.getElementById('promptTableBody');
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="table-empty">暂无 Prompt 模板，请点击"新建 Prompt"</td></tr>';
    } else {
      tbody.innerHTML = filtered.map(function (p) {
        var statusLabel = p.status === 'enabled' ? '已启用' : '已停用';
        var statusCls = p.status === 'enabled' ? 'badge-pass' : 'badge-none';
        var typeLabel = p.prompt_type === 'text_audit' ? '文本审核' : p.prompt_type;
        return '<tr>' +
          '<td><strong>' + escHtml(p.prompt_name) + '</strong></td>' +
          '<td>' + typeLabel + '</td>' +
          '<td><span class="badge ' + statusCls + '">' + statusLabel + '</span></td>' +
          '<td>' + formatTime(p.updatedAt) + '</td>' +
          '<td>' +
            '<button class="btn-link" data-edit-prompt="' + p.id + '">编辑</button> ' +
            '<button class="btn-link" data-delete-prompt="' + p.id + '" style="color:#f56c6c;">删除</button>' +
          '</td>' +
        '</tr>';
      }).join('');
    }

    // Also update dropdowns on other active tabs
    if (document.getElementById('tab-single-test').classList.contains('active')) {
      renderSingleTestSelects();
    }
    if (document.getElementById('tab-batch-test').classList.contains('active')) {
      renderBatchCreateSelects();
    }
  }

  function openPromptEdit(id) {
    var form = document.getElementById('promptForm');
    form.reset();
    document.getElementById('pmId').value = '';

    if (id) {
      currentPromptId = id;
      var p = getPromptById(id);
      if (!p) return;
      document.getElementById('promptEditTitle').textContent = '编辑 Prompt';
      document.getElementById('pmId').value = p.id;
      document.getElementById('pmPromptName').value = p.prompt_name || '';
      document.getElementById('pmSystemPrompt').value = p.system_prompt || '';
      document.getElementById('pmUserPrompt').value = p.user_prompt || '';
      document.getElementById('pmRemark').value = p.remark || '';
      renderParseFieldTags(getParseFieldNames(p));
    } else {
      currentPromptId = null;
      document.getElementById('promptEditTitle').textContent = '新建 Prompt';
      document.getElementById('pmSystemPrompt').value = DEFAULT_SYSTEM_PROMPT;
      document.getElementById('pmUserPrompt').value = DEFAULT_USER_PROMPT;
      renderParseFieldTags(['result', 'label', 'reason']);
    }

    renderPromptVarTags();
    switchMenu('prompt-config-edit');
  }

  function backToPromptList() {
    currentPromptId = null;
    switchMenu('prompt-config');
    renderPromptList();
  }

  function handleSavePrompt(e) {
    e.preventDefault();
    var promptName = (document.getElementById('pmPromptName').value || '').trim();
    var systemPrompt = (document.getElementById('pmSystemPrompt').value || '').trim();
    var userPrompt = (document.getElementById('pmUserPrompt').value || '').trim();
    var remark = (document.getElementById('pmRemark').value || '').trim();

    var parseFields = getCurrentParseFieldNames();

    var errors = [];
    if (!promptName) errors.push('Prompt 名称不能为空');
    if (!systemPrompt) errors.push('System Prompt 不能为空');
    if (!userPrompt) errors.push('User Prompt 不能为空');

    if (errors.length > 0) {
      alert('保存失败：\n' + errors.join('\n'));
      return;
    }

    var nowStr = now();
    var pmId = document.getElementById('pmId').value;

    if (pmId) {
      var p = getPromptById(pmId);
      if (p) {
        p.prompt_name = promptName;
        p.system_prompt = systemPrompt;
        p.user_prompt = userPrompt;
        p.remark = remark;
        p.parse_fields = parseFields;
        p.updatedAt = nowStr;
      }
    } else {
      promptTemplates.push({
        id: generateId('PM'),
        prompt_name: promptName,
        prompt_type: 'text_audit',
        system_prompt: systemPrompt,
        user_prompt: userPrompt,
        status: 'enabled',
        remark: remark,
        parse_fields: parseFields,
        createdAt: nowStr,
        updatedAt: nowStr
      });
    }

    savePromptTemplates();
    backToPromptList();
    renderPromptList();
  }

  function renderPromptVarTags() {
    var sysPrompt = (document.getElementById('pmSystemPrompt').value || '');
    var userPrompt = (document.getElementById('pmUserPrompt').value || '');
    var combined = sysPrompt + '\n' + userPrompt;
    var re = /\{\{(\w+)\}\}/g;
    var vars = {};
    var m;
    while ((m = re.exec(combined)) !== null) {
      vars[m[1]] = true;
    }
    var container = document.getElementById('promptVarTags');
    var keys = Object.keys(vars);
    if (keys.length === 0) {
      container.innerHTML = '<span class="form-hint">可用变量：暂无，请在 Prompt 中使用 <code>{{变量名}}</code> 格式定义变量</span>';
    } else {
      container.innerHTML = '<span class="form-hint">可用变量：</span> ' +
        keys.map(function (k) { return '<code class="var-tag">{{' + k + '}}</code>'; }).join(' ');
    }
  }

  function handleDeletePrompt(id) {
    var p = getPromptById(id);
    if (!p) return;
    if (!confirm('删除后该 Prompt 不可恢复，是否确认删除？')) return;
    promptTemplates = promptTemplates.filter(function (t) { return t.id !== id; });
    savePromptTemplates();
    renderPromptList();
  }

  // ── Cascading Model Select Helper ────────────────────────────────
  function populateCascadingModelSelect(categorySelectId, modelSelectId) {
    var catSelect = document.getElementById(categorySelectId);
    var modelSelect = document.getElementById(modelSelectId);
    var category = catSelect ? catSelect.value : '';
    var curVal = modelSelect ? modelSelect.value : '';

    var filtered = modelConfigs.filter(function (mc) {
      if (mc.status !== 'enabled') return false;
      if (!category) return true;
      return mc.category === category;
    });

    modelSelect.innerHTML = '<option value="">请选择模型配置</option>' +
      filtered.map(function (mc) { return '<option value="' + mc.id + '">' + escHtml(mc.config_name) + ' (' + escHtml(mc.model_name) + ')</option>'; }).join('');

    var found = filtered.some(function (mc) { return String(mc.id) === String(curVal); });
    if (found) modelSelect.value = curVal;
  }

  // ── Shared sensitive-word matching (no LLM) ─────────────────────
  function matchSensitiveWords(combinedText) {
    var enabledRules = rules.filter(function (r) { return r.enabled; });
    var hitLabel = '正常';
    var resultVal = 'pass';
    var reasonText = '未发现明显违规风险';
    var hitKeywords = [];

    enabledRules.forEach(function (rule) {
      if (combinedText.indexOf(rule.keyword) !== -1) {
        hitKeywords.push(rule.keyword);
        if (rule.auditResult === 'violate') {
          resultVal = 'violate';
          if (rule.label.indexOf('涉政') !== -1) hitLabel = '涉政';
          else if (rule.label.indexOf('色情') !== -1) hitLabel = '色情';
          else if (rule.label.indexOf('谩骂') !== -1 || rule.label.indexOf('辱骂') !== -1) hitLabel = '谩骂';
          else if (rule.label.indexOf('灌水') !== -1) hitLabel = '灌水';
          else if (rule.label.indexOf('广告') !== -1) hitLabel = '广告';
          else hitLabel = '违禁';
          reasonText = '文本包含违规内容：' + rule.label;
        } else if (rule.auditResult === 'suspect' && resultVal === 'pass') {
          resultVal = 'violate';
          if (rule.label.indexOf('涉政') !== -1) hitLabel = '涉政';
          else if (rule.label.indexOf('色情') !== -1) hitLabel = '色情';
          else if (rule.label.indexOf('谩骂') !== -1 || rule.label.indexOf('辱骂') !== -1) hitLabel = '谩骂';
          else if (rule.label.indexOf('灌水') !== -1) hitLabel = '灌水';
          else if (rule.label.indexOf('广告') !== -1) hitLabel = '广告';
          else hitLabel = '违禁';
          reasonText = '疑似违规内容：' + rule.label;
        }
      }
    });
    return { auditResult: resultVal, label: hitLabel, reason: reasonText, hitKeywords: hitKeywords };
  }

  // ── LLM API Call ─────────────────────────────────────────────────
  async function callLLM(mcId, systemPrompt, userPrompt) {
    var mc = getModelConfigById(mcId);
    if (!mc) throw new Error('模型配置不存在');

    var apiKey = apiKeysInMemory[mcId];
    if (!apiKey) throw new Error('API Key 未配置，请先在模型接入配置中保存 API Key');

    var body = {
      model: mc.model_name || 'deepseek-chat',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      temperature: mc.temperature != null ? mc.temperature : 0.2,
      max_tokens: mc.max_tokens || 1200,
      stream: false
    };

    var timeoutMs = (mc.timeout_seconds || 30) * 1000;
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, timeoutMs);

    try {
      var response = await fetch(mc.base_url.replace(/\/+$/, '') + '/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + apiKey
        },
        body: JSON.stringify(body),
        signal: controller.signal
      });

      if (!response.ok) {
        var errText = '';
        try { errText = await response.text(); } catch (e) { errText = '无法读取错误信息'; }
        throw new Error('API 请求失败 (' + response.status + '): ' + errText);
      }

      var data = await response.json();
      return data;
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Build prompt by replacing variables ──────────────────────────
  function buildPromptFromTemplate(pt, varValues) {
    var systemPrompt = pt.system_prompt || '';
    var userPrompt = pt.user_prompt || '';
    var keys = Object.keys(varValues);
    for (var i = 0; i < keys.length; i++) {
      var re = new RegExp('\\{\\{' + keys[i] + '\\}\\}', 'g');
      systemPrompt = systemPrompt.replace(re, varValues[keys[i]]);
      userPrompt = userPrompt.replace(re, varValues[keys[i]]);
    }
    return { systemPrompt: systemPrompt, userPrompt: userPrompt };
  }

  // ── Parse LLM response JSON ──────────────────────────────────────
  function parseLLMResponse(llmData) {
    var content = '';
    if (llmData && llmData.choices && llmData.choices.length > 0) {
      content = llmData.choices[0].message.content || '';
    }
    var parsed = null;
    try {
      if (content) parsed = JSON.parse(content.replace(/```json\s*|```/g, '').trim());
    } catch (e) {
      // Return raw content if not valid JSON
    }
    return { raw: content, parsed: parsed };
  }

  // ── Single Test ─────────────────────────────────────────────────
  function renderSingleTestSelects() {
    var promptSelect = document.getElementById('stPromptTemplate');
    var curPromptVal = promptSelect.value;

    document.getElementById('stModelCategory').value = '';
    populateCascadingModelSelect('stModelCategory', 'stModelConfig');

    promptSelect.innerHTML = '<option value="">请选择 Prompt 模板</option>' +
      promptTemplates.filter(function (p) { return p.status === 'enabled'; })
        .map(function (p) { return '<option value="' + p.id + '">' + escHtml(p.prompt_name) + '</option>'; }).join('');

    if (curPromptVal) promptSelect.value = curPromptVal;

    renderSingleTestVarFields(promptSelect.value);
  }

  function renderSingleTestVarFields(promptId) {
    var container = document.getElementById('stVarFields');
    if (!promptId) {
      container.innerHTML = '<p class="form-hint" style="padding:16px 0;">请先选择 Prompt 模板，将根据模板中的变量展示对应输入字段</p>';
      return;
    }
    var pt = getPromptById(promptId);
    if (!pt) {
      container.innerHTML = '<p class="form-hint" style="padding:16px 0;">Prompt 模板不存在</p>';
      return;
    }
    var combined = (pt.system_prompt || '') + '\n' + (pt.user_prompt || '');
    var re = /\{\{(\w+)\}\}/g;
    var vars = {};
    var m;
    while ((m = re.exec(combined)) !== null) {
      vars[m[1]] = true;
    }
    var keys = Object.keys(vars);
    if (keys.length === 0) {
      container.innerHTML = '<p class="form-hint" style="padding:16px 0;">该 Prompt 模板中未包含任何变量，无需输入内容</p>';
      return;
    }
    container.innerHTML = keys.map(function (key) {
      var isContent = key === 'content';
      var inputHtml = isContent
        ? '<textarea id="stVar_' + key + '" class="form-textarea" rows="6" placeholder="请输入' + key + '内容"></textarea>'
        : '<input type="text" id="stVar_' + key + '" class="form-input" placeholder="请输入' + key + '" maxlength="500">';
      return '<div class="form-group">' +
        '<label class="form-label" for="stVar_' + key + '">' + escHtml(key) + ' <span class="required">*</span></label>' +
        inputHtml +
        '</div>';
    }).join('');
  }

  async function handleSingleTest() {
    var mcId = document.getElementById('stModelConfig').value;
    var promptId = document.getElementById('stPromptTemplate').value;

    if (!mcId) { alert('请选择模型配置'); return; }
    if (!promptId) { alert('请选择 Prompt 模板'); return; }

    var pt = getPromptById(promptId);
    if (!pt) { alert('模板不存在'); return; }

    var varValues = {};
    var allEmpty = true;
    var container = document.getElementById('stVarFields');
    var inputs = container.querySelectorAll('[id^="stVar_"]');
    inputs.forEach(function (el) {
      var key = el.id.replace('stVar_', '');
      var val = (el.value || '').trim();
      varValues[key] = val;
      if (val) allEmpty = false;
    });

    if (allEmpty) { alert('请至少填写一个变量内容'); return; }

    var btn = document.getElementById('btnSingleTest');
    btn.disabled = true;
    btn.textContent = '检测中...';
    document.getElementById('stTestStatusText').textContent = '正在调用大模型进行审核...';

    try {
      var prompts = buildPromptFromTemplate(pt, varValues);
      var llmData = await callLLM(mcId, prompts.systemPrompt, prompts.userPrompt);
      var parsed = parseLLMResponse(llmData);
      displaySingleTestResult(parsed, pt.parse_fields);
      document.getElementById('stTestStatusText').textContent = '检测完成';
    } catch (e) {
      document.getElementById('stTestErrorSection').style.display = 'block';
      document.getElementById('stTestError').textContent = e.message;
      document.getElementById('stTestResult').style.display = 'block';
      document.getElementById('stTestRaw').textContent = '';
      document.getElementById('stTestParsed').innerHTML = '';
      document.getElementById('stTestStatusText').textContent = '检测失败';
    }
    btn.disabled = false;
    btn.textContent = '开始检测';
  }

  function displaySingleTestResult(parsed, parseFields) {
    var container = document.getElementById('stTestResult');
    container.style.display = 'block';
    document.getElementById('stTestErrorSection').style.display = 'none';

    document.getElementById('stTestRaw').textContent = parsed.raw || '（无返回内容）';

    var pf = (parseFields && Array.isArray(parseFields) && parseFields.length > 0) ? parseFields : [];
    if (pf.length === 0) {
      document.getElementById('stTestParsed').innerHTML = '<p style="color:#909399;">（未配置解析字段，仅展示原始结果）</p>';
    } else if (parsed.parsed) {
      var html = '';
      for (var i = 0; i < pf.length; i++) {
        var val = parsed.parsed[pf[i]];
        html += '<div class="pr-row"><span class="pr-label">' + escHtml(pf[i]) + '</span><span class="pr-value">' + escHtml(val != null ? String(val) : '') + '</span></div>';
      }
      document.getElementById('stTestParsed').innerHTML = html;
    } else {
      document.getElementById('stTestParsed').innerHTML = '<p style="color:#e6a23c;">LLM 返回结果无法解析为 JSON，请查看原始返回</p>';
    }
  }

  // ── Batch Test ──────────────────────────────────────────────────

  function updateBatchUploadSection(promptId) {
    var section = document.getElementById('btUploadSection');
    if (section) {
      section.style.display = promptId ? '' : 'none';
    }
  }

  function renderBatchCreateSelects() {
    var promptSelect = document.getElementById('btPromptTemplate');
    var curPromptVal = promptSelect.value;

    document.getElementById('btModelCategory').value = '';
    populateCascadingModelSelect('btModelCategory', 'btModelConfig');

    promptSelect.innerHTML = '<option value="">请选择 Prompt 模板</option>' +
      promptTemplates.filter(function (p) { return p.status === 'enabled'; })
        .map(function (p) { return '<option value="' + p.id + '">' + escHtml(p.prompt_name) + '</option>'; }).join('');

    if (curPromptVal) promptSelect.value = curPromptVal;

    updateBatchUploadSection(promptSelect.value);
    updateBatchTemplateHint();
  }

  function handleBatchFileUpload(file) {
    if (!file) return;
    var templateVars = getBatchTemplateVars();
    if (templateVars.length === 0) { alert('请先选择 Prompt 模板，以便确定上传文件的列格式'); return; }
    var requiredCols = templateVars; // content_id is optional (auto-generated)
    var reader = new FileReader();
    reader.onload = function (e) {
      try {
        var wb = XLSX.read(e.target.result, { type: 'array' });
        var sheet = wb.Sheets[wb.SheetNames[0]];
        var rows = XLSX.utils.sheet_to_json(sheet, { defval: '' });
        if (rows.length === 0) { alert('Excel 文件中无数据'); return; }
        if (rows.length > 10000) { alert('单个批量任务最多支持 10000 条，请拆分文件后重新上传。'); return; }
        // Check that at least one var column exists
        var firstRow = rows[0];
        var foundCols = requiredCols.filter(function (c) { return firstRow.hasOwnProperty(c); });
        if (foundCols.length === 0) {
          alert('Excel 文件缺少必要列：' + requiredCols.join('、') + '。请下载模板参考格式。');
          return;
        }
        var contentIds = {};
        var validRows = [];
        var invalidRows = [];
        var autoIdx = 1;
        rows.forEach(function (row, i) {
          var cid = (row.content_id !== undefined ? String(row.content_id) : '').trim();
          var errors = [];
          // content_id auto-generation
          if (!cid) { cid = 'AUTO_' + String(autoIdx).padStart(4, '0'); autoIdx++; }
          // Check duplicates
          if (contentIds[cid]) { errors.push('content_id 重复'); }
          contentIds[cid] = true;
          // Check required var columns
          var hasAllRequired = true;
          requiredCols.forEach(function (col) {
            var val = (row[col] !== undefined ? String(row[col]) : '').trim();
            if (!val) { errors.push(col + '为空'); hasAllRequired = false; }
          });
          // Build entry with all var values
          var entry = { row_index: i + 2, content_id: cid, valid: errors.length === 0, error_message: errors.join('；') };
          requiredCols.forEach(function (col) {
            entry[col] = (row[col] !== undefined ? String(row[col]) : '').trim();
          });
          if (entry.valid) { validRows.push(entry); } else { invalidRows.push(entry); }
        });
        pendingBatchFileData = {
          file_name: file.name,
          file_size: file.size,
          total_count: rows.length,
          valid_count: validRows.length,
          invalid_count: invalidRows.length,
          valid_rows: validRows,
          invalid_rows: invalidRows,
          template_vars: templateVars
        };
        renderFileParsePreview(pendingBatchFileData);
        document.getElementById('btFileInfo').style.display = 'inline-block';
        document.getElementById('btFileInfo').innerHTML =
          '<span class="batch-file-info">' + escHtml(file.name) + ' (' + formatFileSize(file.size) + ')' +
          ' <span class="batch-file-remove" id="btnBtRemoveFile">×</span></span>';
        document.getElementById('btnBtRemoveFile').addEventListener('click', function () {
          pendingBatchFileData = null;
          document.getElementById('btFileInfo').style.display = 'none';
          document.getElementById('btParsePreview').style.display = 'none';
          document.getElementById('btFileInput').value = '';
        });
      } catch (err) {
        alert('Excel 解析失败：' + err.message);
      }
    };
    reader.readAsArrayBuffer(file);
  }

  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  function renderFileParsePreview(data) {
    var container = document.getElementById('btParsePreview');
    var cols = data.template_vars || ['title', 'content']; // fallback
    var html = '<div style="margin-top:12px;padding:12px;background:#fafafa;border-radius:6px;">';
    html += '<h4 style="margin:0 0 8px;">解析结果</h4>';
    html += '<div class="batch-preview-stats">';
    html += '<span class="batch-preview-stat"><strong>' + data.total_count + '</strong> 总行数</span>';
    html += '<span class="batch-preview-stat valid"><strong>' + data.valid_count + '</strong> 有效</span>';
    if (data.invalid_count > 0) {
      html += '<span class="batch-preview-stat invalid"><strong>' + data.invalid_count + '</strong> 无效</span>';
    }
    html += '</div>';
    // Preview table (first 10)
    var previewRows = data.valid_rows.slice(0, 10).concat(data.invalid_rows.slice(0, 10));
    if (previewRows.length > 0) {
      html += '<div class="table-wrap"><table class="batch-preview-table"><thead><tr>';
      html += '<th>行号</th><th>content_id</th>';
      cols.forEach(function (c) { html += '<th>' + escHtml(c) + '</th>'; });
      html += '<th>校验</th><th>说明</th>';
      html += '</tr></thead><tbody>';
      previewRows.forEach(function (r) {
        var cls = r.valid ? '' : ' class="row-invalid"';
        html += '<tr' + cls + '>';
        html += '<td>' + r.row_index + '</td>';
        html += '<td>' + escHtml(r.content_id) + '</td>';
        cols.forEach(function (c) {
          html += '<td>' + escHtml(truncate(r[c] || '', 50)) + '</td>';
        });
        html += '<td>' + (r.valid ? '<span style="color:var(--success);">通过</span>' : '<span style="color:var(--danger);">失败</span>') + '</td>';
        html += '<td>' + escHtml(r.error_message || '-') + '</td>';
        html += '</tr>';
      });
      html += '</tbody></table></div>';
    }
    // Invalid rows notice
    if (data.invalid_count > 0) {
      html += '<div style="margin-top:8px;padding:8px 12px;background:#fef0f0;border-radius:4px;font-size:13px;color:var(--danger);">';
      html += '共解析 ' + data.total_count + ' 条，其中 ' + data.valid_count + ' 条有效，' + data.invalid_count + ' 条无效。是否仅提交有效数据创建任务？';
      html += ' <button type="button" class="btn btn-sm btn-primary" id="btnBtSubmitValid">仅提交有效数据</button>';
      html += ' <button type="button" class="btn btn-sm btn-secondary" id="btnBtCancelUpload">取消并重新上传</button>';
      html += '</div>';
    }
    html += '</div>';
    container.innerHTML = html;
    container.style.display = 'block';

    if (data.invalid_count > 0) {
      document.getElementById('btnBtSubmitValid').addEventListener('click', function () {
        pendingBatchFileData.valid_count = data.valid_count;
        pendingBatchFileData.submit_valid_only = true;
        document.getElementById('btParsePreview').style.display = 'none';
      });
      document.getElementById('btnBtCancelUpload').addEventListener('click', function () {
        pendingBatchFileData = null;
        container.style.display = 'none';
        document.getElementById('btFileInfo').style.display = 'none';
        document.getElementById('btFileInput').value = '';
      });
    }
  }

  function handleCreateBatchTask(e) {
    e.preventDefault();
    var taskName = (document.getElementById('btTaskName').value || '').trim();
    var mcId = document.getElementById('btModelConfig').value;
    var promptId = document.getElementById('btPromptTemplate').value;

    var errors = [];
    if (!taskName) errors.push('任务名称不能为空');
    if (!mcId) errors.push('请选择模型配置');
    if (!promptId) errors.push('请选择 Prompt 模板');
    if (!pendingBatchFileData || pendingBatchFileData.valid_count === 0) errors.push('请上传有效的 Excel 文件');

    if (errors.length > 0) { alert('创建失败：\n' + errors.join('\n')); return; }

    var mc = getModelConfigById(mcId);
    if (!mc) { alert('模型配置不存在'); return; }
    var pt = getPromptById(promptId);
    if (!pt) { alert('模板不存在'); return; }

    var nowStr = now();
    var tmplVars = pendingBatchFileData.template_vars || ['title', 'content'];
    var items = pendingBatchFileData.valid_rows.map(function (r) {
      var item = {
        item_id: generateId('BI'),
        content_id: r.content_id,
        audit_result: '',
        label: '',
        reason: '',
        raw_response: '',
        detect_status: 'pending',
        fail_reason: '',
        cost_time: 0,
        completed_at: ''
      };
      tmplVars.forEach(function (v) { item[v] = r[v] || ''; });
      return item;
    });

    var task = {
      task_id: generateId('BT'),
      task_name: taskName,
      audit_type: 'text',
      model_config_id: mcId,
      model_config_name: mc.config_name,
      prompt_template_id: promptId,
      prompt_template_name: pt.prompt_name,
      file_name: pendingBatchFileData.file_name,
      template_vars: tmplVars,
      parse_fields: (pt.parse_fields && Array.isArray(pt.parse_fields)) ? pt.parse_fields.slice() : [],
      task_status: 'pending',
      progress: 0,
      total_count: items.length,
      pending_count: items.length,
      processing_count: 0,
      success_count: 0,
      failed_count: 0,
      cancelled_count: 0,
      pass_count: 0,
      suspect_count: 0,
      violate_count: 0,
      remark: '',
      current_index: 0,
      items: items,
      created_at: nowStr,
      started_at: '',
      completed_at: ''
    };

    batchTasks.unshift(task);
    saveBatchTasks();

    // Reset form
    document.getElementById('btTaskName').value = '';
    document.getElementById('btFileInput').value = '';
    document.getElementById('btFileInfo').style.display = 'none';
    document.getElementById('btParsePreview').style.display = 'none';
    pendingBatchFileData = null;
    document.getElementById('btCreateStatus').textContent = '任务创建成功，正在执行检测...';

    startBatchProcessing(task.task_id);
    renderBatchTaskList();
    renderBatchProgress();

    setTimeout(function () {
      document.getElementById('btCreateStatus').textContent = '';
    }, 3000);
  }

  function startBatchProcessing(taskId) {
    var task = getBatchTaskById(taskId);
    if (!task || task.task_status === 'cancelled' || task.task_status === 'completed') return;
    task.task_status = 'running';
    if (!task.started_at) task.started_at = now();
    saveBatchTasks();
    renderBatchProgress();
    renderBatchTaskList();

    processNextBatchItem(taskId);
  }

  async function processNextBatchItem(taskId) {
    var task = getBatchTaskById(taskId);
    if (!task || task.task_status !== 'running') return;

    // Find next pending item
    var idx = task.current_index || 0;
    var item = null;
    while (idx < task.items.length) {
      if (task.items[idx].detect_status === 'pending') {
        item = task.items[idx];
        break;
      }
      idx++;
    }

    if (!item) {
      // All done
      task.progress = 100;
      task.current_index = task.items.length;
      task.pending_count = 0;
      task.task_status = task.failed_count > 0 && task.success_count > 0 ? 'partial_failed'
        : task.failed_count === task.total_count ? 'failed' : 'completed';
      task.completed_at = now();
      saveBatchTasks();
      renderBatchProgress();
      renderBatchTaskList();
      return;
    }

    task.current_index = idx;
    task.processing_count = 1;
    task.pending_count--;
    item.detect_status = 'processing';
    saveBatchTasks();
    renderBatchProgress();

    var startTime = Date.now();

    try {
      var pt = getPromptById(task.prompt_template_id);
      if (!pt) throw new Error('Prompt 模板不存在');

      var varValues = {};
      (task.template_vars || []).forEach(function (v) { varValues[v] = item[v] || ''; });
      var prompts = buildPromptFromTemplate(pt, varValues);

      var llmData = await callLLM(task.model_config_id, prompts.systemPrompt, prompts.userPrompt);
      var parsed = parseLLMResponse(llmData);

      // Reload task to avoid overwriting changes made during async call
      task = getBatchTaskById(taskId);
      if (!task) return;
      var reloadedItem = task.items[idx];
      if (!reloadedItem || reloadedItem.detect_status === 'cancelled') {
        // Item was cancelled during processing
        processNextBatchItem(taskId);
        return;
      }

      reloadedItem.raw_response = parsed.raw;
      if (parsed.parsed) {
        var pf = (task.parse_fields && task.parse_fields.length > 0) ? task.parse_fields : ['result', 'label', 'reason'];
        reloadedItem.audit_result = parsed.parsed[pf[0]] || '';
        reloadedItem.label = parsed.parsed[pf[1]] || '';
        reloadedItem.reason = parsed.parsed[pf[2]] || '';
      }
      reloadedItem.detect_status = 'success';
      reloadedItem.cost_time = Date.now() - startTime;
      reloadedItem.completed_at = now();
      task.success_count++;

      if (reloadedItem.audit_result === 'violate' || reloadedItem.audit_result === 'reject') task.violate_count++;
      else if (reloadedItem.audit_result === 'suspect') task.suspect_count++;
      else task.pass_count++;

    } catch (e) {
      task = getBatchTaskById(taskId);
      if (!task) return;
      var errItem = task.items[idx];
      if (!errItem || errItem.detect_status === 'cancelled') {
        processNextBatchItem(taskId);
        return;
      }
      errItem.detect_status = 'failed';
      errItem.fail_reason = e.message;
      errItem.cost_time = Date.now() - startTime;
      errItem.completed_at = now();
      task.failed_count++;
    }

    task.processing_count = 0;
    saveBatchTasks();
    renderBatchProgress();
    renderBatchTaskList();

    // Process next item
    processNextBatchItem(taskId);
  }

  function processBatchItem(taskId) {
    // Async processing is now handled by processNextBatchItem
  }

  function pauseBatchTask(taskId) {
    var task = getBatchTaskById(taskId);
    if (!task || task.task_status !== 'running') return;
    task.task_status = 'paused';
    if (activeBatchTimer) { clearInterval(activeBatchTimer); activeBatchTimer = null; }
    saveBatchTasks();
    renderBatchProgress();
    renderBatchTaskList();
    if (document.getElementById('tab-batch-test-detail').classList.contains('active')) {
      renderBatchTaskDetail(taskId);
    }
  }

  function resumeBatchTask(taskId) {
    var task = getBatchTaskById(taskId);
    if (!task || task.task_status !== 'paused') return;
    task.task_status = 'running';
    saveBatchTasks();
    startBatchProcessing(taskId);
    renderBatchProgress();
    renderBatchTaskList();
    if (document.getElementById('tab-batch-test-detail').classList.contains('active')) {
      renderBatchTaskDetail(taskId);
    }
  }

  function cancelBatchTask(taskId) {
    var task = getBatchTaskById(taskId);
    if (!task) return;
    if (task.task_status !== 'pending' && task.task_status !== 'running' && task.task_status !== 'paused') return;
    if (!confirm('确认取消该批量检测任务吗？取消后未检测内容将不再继续执行，已完成结果会保留。')) return;
    if (activeBatchTimer) { clearInterval(activeBatchTimer); activeBatchTimer = null; }
    task.task_status = 'cancelled';
    task.completed_at = now();
    // Mark remaining pending items as cancelled (processing item will finish naturally)
    for (var i = task.current_index; i < task.items.length; i++) {
      if (task.items[i].detect_status === 'pending') {
        task.items[i].detect_status = 'cancelled';
        task.items[i].fail_reason = '任务已取消，未执行检测';
        task.cancelled_count++;
        task.pending_count = Math.max(0, task.pending_count - 1);
      }
    }
    var processed = task.success_count + task.failed_count + task.cancelled_count;
    task.progress = Math.round((processed / task.total_count) * 100);
    saveBatchTasks();
    renderBatchProgress();
    renderBatchTaskList();
    if (document.getElementById('tab-batch-test-detail').classList.contains('active')) {
      renderBatchTaskDetail(taskId);
    }
  }

  function renderBatchProgress() {
    var card = document.getElementById('batchProgressCard');
    // Find first running or paused task
    var activeTask = null;
    for (var i = 0; i < batchTasks.length; i++) {
      if (batchTasks[i].task_status === 'running' || batchTasks[i].task_status === 'paused') {
        activeTask = batchTasks[i];
        break;
      }
    }
    if (!activeTask) { card.style.display = 'none'; return; }
    card.style.display = 'block';

    var t = activeTask;
    var fillCls = t.task_status === 'paused' ? ' partial' : '';
    if (t.task_status === 'completed') fillCls = ' completed';

    var content = document.getElementById('btProgressContent');
    content.innerHTML =
      '<p style="margin:0 0 8px;font-weight:500;">' + escHtml(t.task_name) +
      ' <span class="batch-status batch-status-' + t.task_status + '">' + batchTaskStatusLabel(t.task_status) + '</span></p>' +
      '<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">' +
        '<div class="batch-progress-bar" style="flex:1;"><div class="batch-progress-fill' + fillCls + '" style="width:' + t.progress + '%;"></div></div>' +
        '<span style="font-size:14px;font-weight:600;white-space:nowrap;">' + t.progress + '%</span>' +
      '</div>' +
      '<p style="font-size:12px;color:var(--text-muted);margin:0 0 8px;">已处理：' + (t.success_count + t.failed_count + t.cancelled_count) + ' / ' + t.total_count + '</p>' +
      '<div class="batch-stats">' +
        '<div class="batch-stat-card"><div class="stat-num">' + t.total_count + '</div><div class="stat-label">总数</div></div>' +
        '<div class="batch-stat-card"><div class="stat-num">' + t.pending_count + '</div><div class="stat-label">待检测</div></div>' +
        '<div class="batch-stat-card"><div class="stat-num">' + t.success_count + '</div><div class="stat-label">成功</div></div>' +
        '<div class="batch-stat-card failed"><div class="stat-num">' + t.failed_count + '</div><div class="stat-label">失败</div></div>' +
        '<div class="batch-stat-card pass"><div class="stat-num">' + t.pass_count + '</div><div class="stat-label">通过</div></div>' +
        '<div class="batch-stat-card violate"><div class="stat-num">' + t.violate_count + '</div><div class="stat-label">违规</div></div>' +
      '</div>';

    var actions = document.getElementById('btProgressActions');
    var actionHtml = '';
    if (t.task_status === 'running') {
      actionHtml = '<button class="btn btn-sm btn-warning" data-batch-pause="' + t.task_id + '">暂停</button> ' +
                   '<button class="btn btn-sm btn-danger" data-batch-cancel="' + t.task_id + '">取消</button>';
    } else if (t.task_status === 'paused') {
      actionHtml = '<button class="btn btn-sm btn-primary" data-batch-resume="' + t.task_id + '">继续</button> ' +
                   '<button class="btn btn-sm btn-danger" data-batch-cancel="' + t.task_id + '">取消</button>';
    }
    actions.innerHTML = actionHtml;
  }

  function renderBatchTaskList() {
    var filterStatus = document.getElementById('filterBtStatus').value;
    var search = (document.getElementById('filterBtSearch').value || '').trim().toLowerCase();

    var filtered = batchTasks.filter(function (t) {
      var statusMatch = !filterStatus || t.task_status === filterStatus;
      var searchMatch = !search ||
        t.task_name.toLowerCase().indexOf(search) !== -1 ||
        t.task_id.toLowerCase().indexOf(search) !== -1;
      return statusMatch && searchMatch;
    });

    filtered.sort(function (a, b) {
      return (b.created_at || '').localeCompare(a.created_at || '');
    });

    var tbody = document.getElementById('batchTaskTableBody');
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="12" class="table-empty">暂无批量检测任务</td></tr>';
    } else {
      tbody.innerHTML = filtered.map(function (t) {
        var statusLabel = batchTaskStatusLabel(t.task_status);
        var progressHtml = '<div style="display:flex;align-items:center;gap:6px;">' +
          '<div class="batch-progress-bar" style="flex:1;min-width:60px;"><div class="batch-progress-fill" style="width:' + t.progress + '%;"></div></div>' +
          '<span style="font-size:12px;">' + t.progress + '%</span></div>';
        var ops = '<button class="btn-link" data-batch-detail="' + t.task_id + '">详情</button> ';
        if (t.task_status === 'running') {
          ops += '<button class="btn-link" data-batch-pause="' + t.task_id + '">暂停</button> ';
          ops += '<button class="btn-link" data-batch-cancel="' + t.task_id + '" style="color:#f56c6c;">取消</button>';
        } else if (t.task_status === 'paused') {
          ops += '<button class="btn-link" data-batch-resume="' + t.task_id + '">继续</button> ';
          ops += '<button class="btn-link" data-batch-cancel="' + t.task_id + '" style="color:#f56c6c;">取消</button>';
        } else if (t.task_status === 'pending') {
          ops += '<button class="btn-link" data-batch-cancel="' + t.task_id + '" style="color:#f56c6c;">取消</button>';
        }
        if (t.task_status === 'completed' || t.task_status === 'partial_failed' || t.task_status === 'cancelled') {
          ops += '<button class="btn-link" data-batch-export="' + t.task_id + '">导出</button> ';
        }
        if (t.task_status !== 'running') {
          ops += '<button class="btn-link" data-batch-delete="' + t.task_id + '" style="color:#f56c6c;">删除</button>';
        }
        return '<tr>' +
          '<td><code style="font-size:12px;">' + escHtml(t.task_id) + '</code></td>' +
          '<td><strong>' + escHtml(t.task_name) + '</strong></td>' +
          '<td>' + escHtml(t.model_config_name) + '</td>' +
          '<td>' + escHtml(t.prompt_template_name) + '</td>' +
          '<td><span class="batch-status batch-status-' + t.task_status + '">' + statusLabel + '</span></td>' +
          '<td>' + progressHtml + '</td>' +
          '<td>' + t.total_count + '</td>' +
          '<td style="color:var(--success);">' + t.pass_count + '</td>' +
          '<td style="color:var(--danger);">' + t.violate_count + '</td>' +
          '<td style="color:var(--danger);">' + t.failed_count + '</td>' +
          '<td>' + formatTime(t.created_at) + '</td>' +
          '<td style="white-space:nowrap;">' + ops + '</td>' +
          '</tr>';
      }).join('');
    }
    document.getElementById('batchTaskCount').textContent = '共 ' + filtered.length + ' 条';
  }

  function openBatchDetail(taskId) {
    currentBatchTaskId = taskId;
    switchMenu('batch-test-detail');
    renderBatchTaskDetail(taskId);
  }

  function renderBatchTaskDetail(taskId) {
    var t = getBatchTaskById(taskId);
    if (!t) return;
    document.getElementById('btDetailTitle').textContent = '任务详情 - ' + t.task_name;

    var statusLabel = batchTaskStatusLabel(t.task_status);
    var fillCls = t.task_status === 'completed' ? ' completed' : (t.task_status === 'partial_failed' ? ' partial' : (t.task_status === 'failed' ? ' failed' : ''));

    var html = '';

    // Progress stats (no progress bar, only 总数/待检测/成功/失败)
    html += '<h4 style="margin:16px 0 8px;">任务进度统计</h4>';
    html += '<div class="batch-stats">' +
      '<div class="batch-stat-card"><div class="stat-num">' + t.total_count + '</div><div class="stat-label">总数</div></div>' +
      '<div class="batch-stat-card"><div class="stat-num">' + t.pending_count + '</div><div class="stat-label">待检测</div></div>' +
      '<div class="batch-stat-card"><div class="stat-num">' + t.success_count + '</div><div class="stat-label">成功</div></div>' +
      '<div class="batch-stat-card failed"><div class="stat-num">' + t.failed_count + '</div><div class="stat-label">失败</div></div>' +
      '</div>';

    // Action buttons (only 暂停/继续/取消, no export/delete)
    var actionHtml = '';
    if (t.task_status === 'running') {
      actionHtml = '<button class="btn btn-sm btn-warning" data-batch-pause="' + t.task_id + '">暂停</button> ' +
                   '<button class="btn btn-sm btn-danger" data-batch-cancel="' + t.task_id + '">取消</button>';
    } else if (t.task_status === 'paused') {
      actionHtml = '<button class="btn btn-sm btn-primary" data-batch-resume="' + t.task_id + '">继续</button> ' +
                   '<button class="btn btn-sm btn-danger" data-batch-cancel="' + t.task_id + '">取消</button>';
    }
    document.getElementById('btDetailActions').innerHTML = actionHtml;

    // Detail items
    html += '<h4 style="margin:16px 0 8px;">检测明细</h4>';
    var tmplVars = t.template_vars || ['title', 'content'];
    var pf = getParseFieldNames(t);
    html += '<div class="table-wrap"><table class="table"><thead><tr>' +
      '<th>序号</th><th>content_id</th>';
    tmplVars.forEach(function (v) { html += '<th>' + escHtml(v) + '</th>'; });
    html += '<th>检测状态</th><th>检测耗时</th>';
    pf.forEach(function (f) { html += '<th>' + escHtml(f) + '</th>'; });
    html += '<th>原始结果</th>' +
      '</tr></thead><tbody id="btDetailItemsBody"></tbody></table></div>';
    html += '<div id="btDetailPagination" class="batch-pagination"></div>';

    document.getElementById('btDetailContent').innerHTML = html;

    renderBatchDetailItems(taskId);
  }

  function renderBatchDetailItems(taskId) {
    var t = getBatchTaskById(taskId);
    if (!t) return;
    var allItems = t.items;

    var pageSize = 20;
    var totalPages = Math.ceil(allItems.length / pageSize) || 1;
    var page = (t._detailPage || 1);
    if (page > totalPages) page = totalPages;
    t._detailPage = page;
    var start = (page - 1) * pageSize;
    var pageItems = allItems.slice(start, start + pageSize);

    var tmplVars = t.template_vars || ['title', 'content'];
    var pf = getParseFieldNames(t);
    var totalCols = 2 + tmplVars.length + 2 + pf.length + 1; // 序号+content_id+tmplVars+状态+耗时+pf+原始结果

    var tbody = document.getElementById('btDetailItemsBody');
    if (pageItems.length === 0) {
      tbody.innerHTML = '<tr><td colspan="' + totalCols + '" class="table-empty">暂无匹配的检测记录</td></tr>';
    } else {
      tbody.innerHTML = pageItems.map(function (item, i) {
        var statusLabel = '';
        if (item.detect_status === 'pending') statusLabel = '<span class="batch-status batch-status-pending">待检测</span>';
        else if (item.detect_status === 'processing') statusLabel = '<span class="batch-status batch-status-running">检测中</span>';
        else if (item.detect_status === 'success') statusLabel = '<span class="batch-status batch-status-completed">成功</span>';
        else if (item.detect_status === 'failed') statusLabel = '<span class="batch-status batch-status-failed">失败</span>';
        else if (item.detect_status === 'cancelled') statusLabel = '<span class="batch-status batch-status-cancelled">已取消</span>';

        var rowHtml = '<tr>' +
          '<td>' + (start + i + 1) + '</td>' +
          '<td><code style="font-size:12px;">' + escHtml(item.content_id) + '</code></td>';
        tmplVars.forEach(function (v) {
          rowHtml += '<td>' + escHtml(truncate(item[v] || '', 40)) + '</td>';
        });
        rowHtml += '<td>' + statusLabel + '</td>' +
          '<td>' + (item.cost_time ? item.cost_time + 'ms' : '-') + '</td>';
        var mappedValues = [item.audit_result, item.label, item.reason];
        for (var fi = 0; fi < pf.length; fi++) {
          var val = fi < mappedValues.length ? mappedValues[fi] : '';
          rowHtml += '<td>' + escHtml(val || '-') + '</td>';
        }
        // 原始结果：失败时展示失败原因，成功时展示原始返回
        var rawDisplay = '';
        if (item.detect_status === 'failed') {
          rawDisplay = escHtml(item.fail_reason || '检测失败');
        } else if (item.detect_status === 'success' && item.raw_response) {
          rawDisplay = '<code style="font-size:11px;">' + escHtml(truncate(item.raw_response, 80)) + '</code>';
        } else {
          rawDisplay = '<span style="color:var(--text-muted);">-</span>';
        }
        rowHtml += '<td>' + rawDisplay + '</td>' +
          '</tr>';
        return rowHtml;
      }).join('');
    }

    // Pagination
    var pagEl = document.getElementById('btDetailPagination');
    if (totalPages <= 1) {
      pagEl.innerHTML = '';
    } else {
      var pagHtml = '<button ' + (page <= 1 ? 'disabled' : '') + ' data-bt-page="' + (page - 1) + '">上一页</button>';
      for (var p = 1; p <= totalPages; p++) {
        pagHtml += '<button class="' + (p === page ? 'active' : '') + '" data-bt-page="' + p + '">' + p + '</button>';
      }
      pagHtml += '<button ' + (page >= totalPages ? 'disabled' : '') + ' data-bt-page="' + (page + 1) + '">下一页</button>';
      pagHtml += '<span class="page-info">共 ' + allItems.length + ' 条 ' + totalPages + ' 页</span>';
      pagEl.innerHTML = pagHtml;
      pagEl.querySelectorAll('[data-bt-page]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          t._detailPage = parseInt(this.getAttribute('data-bt-page'));
          renderBatchDetailItems(taskId);
        });
      });
    }
  }

  function openBatchItemModal(taskId, itemId) {
    var t = getBatchTaskById(taskId);
    if (!t) return;
    var item = t.items.filter(function (it) { return it.item_id === itemId; })[0];
    if (!item) return;

    var detectStatusLabel = '';
    if (item.detect_status === 'pending') detectStatusLabel = '待检测';
    else if (item.detect_status === 'success') detectStatusLabel = '成功';
    else if (item.detect_status === 'failed') detectStatusLabel = '失败';
    else if (item.detect_status === 'cancelled') detectStatusLabel = '已取消';
    else detectStatusLabel = item.detect_status;

    var resultBadge = '';
    if (item.audit_result === 'pass') resultBadge = '<span class="badge badge-pass">通过</span>';
    else if (item.audit_result === 'violate') resultBadge = '<span class="badge badge-violate">违规</span>';
    else resultBadge = '<span style="color:var(--text-muted);">-</span>';

    var tmplVars = t.template_vars || ['title', 'content'];
    var pf = getParseFieldNames(t);
    var html = '<div class="detail-grid">';
    html += '<div class="detail-item"><div class="detail-label">content_id</div><div class="detail-value"><code>' + escHtml(item.content_id) + '</code></div></div>';
    html += '<div class="detail-item"><div class="detail-label">检测状态</div><div class="detail-value">' + detectStatusLabel + '</div></div>';
    tmplVars.forEach(function (v) {
      html += '<div class="detail-item detail-item-wide"><div class="detail-label">' + escHtml(v) + '</div><div class="detail-value" style="white-space:pre-wrap;">' + escHtml(item[v] || '') + '</div></div>';
    });
    var mappedValues = [item.audit_result, item.label, item.reason];
    for (var fi = 0; fi < pf.length; fi++) {
      var val = fi < mappedValues.length ? mappedValues[fi] : '';
      if (fi === 0) {
        var resultBadge = '';
        if (val === 'pass') resultBadge = '<span class="badge badge-pass">通过</span>';
        else if (val === 'violate') resultBadge = '<span class="badge badge-violate">违规</span>';
        else resultBadge = '<span style="color:var(--text-muted);">-</span>';
        html += '<div class="detail-item"><div class="detail-label">' + escHtml(pf[fi]) + '</div><div class="detail-value">' + resultBadge + '</div></div>';
      } else if (fi === 2) {
        html += '<div class="detail-item detail-item-wide"><div class="detail-label">' + escHtml(pf[fi]) + '</div><div class="detail-value">' + escHtml(val || '-') + '</div></div>';
      } else {
        html += '<div class="detail-item"><div class="detail-label">' + escHtml(pf[fi]) + '</div><div class="detail-value">' + escHtml(val || '-') + '</div></div>';
      }
    }
    html += '<div class="detail-item detail-item-wide"><div class="detail-label">模型原始返回</div><div class="detail-value"><pre style="background:#fafafa;padding:8px;border-radius:4px;font-size:12px;">' + escHtml(item.raw_response || '-') + '</pre></div></div>';
    html += '<div class="detail-item"><div class="detail-label">检测耗时</div><div class="detail-value">' + (item.cost_time ? item.cost_time + 'ms' : '-') + '</div></div>';
    html += '<div class="detail-item"><div class="detail-label">失败原因</div><div class="detail-value">' + escHtml(item.fail_reason || '-') + '</div></div>';
    html += '<div class="detail-item"><div class="detail-label">完成时间</div><div class="detail-value">' + formatTime(item.completed_at) + '</div></div>';
    html += '</div>';

    document.getElementById('batchItemModalContent').innerHTML = html;
    document.getElementById('batchItemModal').style.display = 'flex';
  }

  function exportBatchResults(taskId) {
    var t = getBatchTaskById(taskId);
    if (!t || !window.XLSX) return;
    var tmplVars = t.template_vars || ['title', 'content'];
    var pf = getParseFieldNames(t);
    var exportData = t.items.map(function (item) {
      var row = {
        task_id: t.task_id,
        task_name: t.task_name,
        content_id: item.content_id,
        detect_status: item.detect_status,
        fail_reason: item.fail_reason,
        cost_time: item.cost_time,
        raw_response: item.raw_response,
        completed_at: formatTime(item.completed_at)
      };
      var mappedValues = [item.audit_result, item.label, item.reason];
      for (var i = 0; i < pf.length; i++) {
        row[pf[i]] = i < mappedValues.length ? mappedValues[i] : '';
      }
      tmplVars.forEach(function (v) { row[v] = item[v] || ''; });
      return row;
    });
    var ws = XLSX.utils.json_to_sheet(exportData);
    var wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, '检测结果');
    XLSX.writeFile(wb, 'batch_result_' + t.task_id + '.xlsx');
  }

  function getBatchTemplateVars() {
    var promptId = document.getElementById('btPromptTemplate').value;
    if (!promptId) return [];
    var pt = getPromptById(promptId);
    if (!pt) return [];
    var combined = (pt.system_prompt || '') + '\n' + (pt.user_prompt || '');
    var re = /\{\{(\w+)\}\}/g;
    var vars = {};
    var m;
    while ((m = re.exec(combined)) !== null) {
      vars[m[1]] = true;
    }
    return Object.keys(vars);
  }

  function updateBatchTemplateHint() {
    var vars = getBatchTemplateVars();
    var hintEl = document.getElementById('btTemplateHint');
    var uploadHintEl = document.getElementById('btUploadHint');
    if (vars.length === 0) {
      hintEl.style.display = 'none';
      uploadHintEl.textContent = '仅支持 .xlsx 格式，最大 50MB，单次最多 10000 条';
      return;
    }
    var cols = ['content_id'].concat(vars).join('、');
    hintEl.style.display = 'inline';
    hintEl.textContent = '模板列：' + cols;
    uploadHintEl.textContent = '仅支持 .xlsx 格式，最大 50MB，单次最多 10000 条。模板列：content_id、' + vars.join('、');
  }

  function downloadBatchTemplate() {
    if (!window.XLSX) return;
    var vars = getBatchTemplateVars();
    var cols = ['content_id'].concat(vars);
    // Build 2 example rows
    var row1 = { content_id: '10001' };
    var row2 = { content_id: '10002' };
    vars.forEach(function (v) {
      row1[v] = '示例' + v + '1';
      row2[v] = '示例' + v + '2';
    });
    var templateData = [row1, row2];
    var ws = XLSX.utils.json_to_sheet(templateData);
    var wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, '模板');
    XLSX.writeFile(wb, 'batch_text_audit_template.xlsx');
  }

  function handleDeleteBatchTask(taskId) {
    var t = getBatchTaskById(taskId);
    if (!t) return;
    if (t.task_status === 'running') { alert('执行中的任务无法删除，请先暂停或取消。'); return; }
    if (!confirm('确认删除该批量任务记录吗？')) return;
    batchTasks = batchTasks.filter(function (t) { return t.task_id !== taskId; });
    saveBatchTasks();
    renderBatchTaskList();
    renderBatchProgress();
  }

  // ── Reset Form ─────────────────────────────────────────────────
  function resetForm() {
    document.getElementById('detectForm').reset();
    document.getElementById('title').value = '';
    document.getElementById('textContent').value = '';
    document.getElementById('textCharCount').textContent = '0 / 10000';
    document.getElementById('imageFile').value = '';
    document.getElementById('videoFile').value = '';
    document.getElementById('imagePreview').style.display = 'none';
    document.getElementById('videoPreview').style.display = 'none';
    document.getElementById('resultCard').style.display = 'none';
    document.getElementById('imageError').textContent = '';
    document.getElementById('videoError').textContent = '';
    setContentType('text');
  }

  // ── Annotation Workbench ──────────────────────────────────────
  var annoState = {
    mode: 'imageMulti',
    dataset: [],
    tags: [],
    page: 1,
    pageSize: 12
  };

  var STORAGE_ANNO_TAGS = 'content_detection_anno_tags';

  function loadAnnoTags() {
    try {
      var stored = localStorage.getItem(STORAGE_ANNO_TAGS);
      if (stored) {
        var parsed = JSON.parse(stored);
        annoState.tags = Array.isArray(parsed) ? parsed : [];
      }
      if (!annoState.tags.length) annoState.tags = ['涉政', '违禁', '色情', '广告', '暴恐', '未成年'];
    } catch (e) {
      annoState.tags = ['涉政', '违禁', '色情', '广告', '暴恐', '未成年'];
    }
  }
  function saveAnnoTags() {
    localStorage.setItem(STORAGE_ANNO_TAGS, JSON.stringify(annoState.tags));
  }

  function renderAnnoTagList() {
    var container = document.getElementById('annoTagList');
    if (!container) return;
    container.innerHTML = annoState.tags.map(function (t) {
      return '<span class="anno-tag-pill">' + escapeHtmlAnno(t) + '<button onclick="window._annoRemoveTag(\'' + escapeHtmlAnno(t) + '\')">&times;</button></span>';
    }).join('');
    var countEl = document.getElementById('annoTagCount');
    if (countEl) countEl.textContent = annoState.tags.length;
  }

  window._annoRemoveTag = function (tagName) {
    if (!confirm('删除标签"' + tagName + '"? 将从所有已标注项中移除该标签标记')) return;
    annoState.tags = annoState.tags.filter(function (t) { return t !== tagName; });
    saveAnnoTags();
    renderAnnoTagList();
    if (annoState.mode === 'imageMulti' || annoState.mode === 'textMulti') {
      annoState.dataset.forEach(function (item) {
        if (item.tags) item.tags = item.tags.filter(function (t) { return t !== tagName; });
      });
      renderAnnoCurrentPage();
      updateAnnoStatus();
    }
  };

  function addAnnoTags() {
    var input = document.getElementById('annoNewTagInput');
    if (!input || !input.value.trim()) return;
    var newTags = input.value.split(/[，,、\n\s]+/).map(function (s) { return s.trim(); }).filter(function (s) { return s.length > 0; });
    var merged = [];
    annoState.tags.concat(newTags).forEach(function (t) { if (merged.indexOf(t) === -1) merged.push(t); });
    if (merged.length > 25) { alert('最多支持25个标签'); return; }
    annoState.tags = merged;
    saveAnnoTags();
    renderAnnoTagList();
    input.value = '';
    if (annoState.dataset.length) renderAnnoCurrentPage();
  }

  function clearAnnoTags() {
    if (!confirm('删除所有标签会同时清除已有标注中的标签信息，确定吗？')) return;
    annoState.tags = [];
    saveAnnoTags();
    renderAnnoTagList();
    if (annoState.mode === 'imageMulti' || annoState.mode === 'textMulti') {
      annoState.dataset.forEach(function (item) { if (item.tags) item.tags = []; });
      renderAnnoCurrentPage();
      updateAnnoStatus();
    }
  }

  function updateAnnoStatus() {
    var total = annoState.dataset.length;
    var completed = 0;
    if (annoState.mode === 'imageMulti' || annoState.mode === 'textMulti') {
      completed = annoState.dataset.filter(function (item) { return item.tags && item.tags.length > 0; }).length;
    } else if (annoState.mode === 'imageEval') {
      completed = annoState.dataset.filter(function (item) { return item.status && item.status !== ''; }).length;
    }
    var doneEl = document.getElementById('annoDoneCount');
    var totalEl = document.getElementById('annoTotalCount');
    if (doneEl) doneEl.textContent = completed;
    if (totalEl) totalEl.textContent = total;
  }

  function renderAnnoCurrentPage() {
    if (!annoState.dataset.length) {
      var dc = document.getElementById('annoDataContainer');
      if (dc) dc.innerHTML = '<div style="text-align:center;padding:48px;color:var(--text-muted);">暂无数据，请通过上方导入区域加载内容</div>';
      var pg = document.getElementById('annoPagination');
      if (pg) pg.innerHTML = '';
      updateAnnoStatus();
      return;
    }
    var start = (annoState.page - 1) * annoState.pageSize;
    var pageData = annoState.dataset.slice(start, start + annoState.pageSize);
    var container = document.getElementById('annoDataContainer');
    var isGrid = (annoState.mode !== 'textMulti');
    if (container) container.className = isGrid ? 'anno-gallery' : 'anno-gallery list-view';

    var html = '';
    for (var i = 0; i < pageData.length; i++) {
      var item = pageData[i];
      var gIdx = annoState.dataset.indexOf(item);
      if (annoState.mode === 'imageMulti') {
        html += renderAnnoImageMultiCard(item, gIdx);
      } else if (annoState.mode === 'imageEval') {
        html += renderAnnoImageEvalCard(item, gIdx);
      } else if (annoState.mode === 'textMulti') {
        html += renderAnnoTextMultiCard(item, gIdx);
      }
    }
    if (container) container.innerHTML = html;

    var totalPages = Math.ceil(annoState.dataset.length / annoState.pageSize);
    var pagDiv = document.getElementById('annoPagination');
    if (pagDiv) {
      if (totalPages <= 1) { pagDiv.innerHTML = ''; }
      else {
        pagDiv.innerHTML =
          '<button ' + (annoState.page === 1 ? 'disabled' : '') + ' onclick="window._annoChangePage(-1)">上一页</button>' +
          '<span class="page-info">第 ' + annoState.page + ' / ' + totalPages + ' 页</span>' +
          '<button ' + (annoState.page >= totalPages ? 'disabled' : '') + ' onclick="window._annoChangePage(1)">下一页</button>' +
          '<input type="number" id="annoJumpInput" min="1" max="' + totalPages + '" style="width:70px;text-align:center;border:1px solid var(--border);border-radius:4px;padding:4px;">' +
          '<button onclick="window._annoJumpPage()">跳转</button>';
      }
    }
    updateAnnoStatus();
    bindAnnoImageZoom();
  }

  function bindAnnoImageZoom() {
    var imgs = document.querySelectorAll('.anno-card-img');
    for (var i = 0; i < imgs.length; i++) {
      imgs[i].onclick = function () {
        var src = this.getAttribute('data-src') || this.src;
        if (src) {
          document.getElementById('annoModalImage').src = src;
          document.getElementById('annoImageModal').style.display = 'flex';
        }
      };
    }
  }

  window._annoChangePage = function (delta) {
    annoState.page += delta;
    renderAnnoCurrentPage();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };
  window._annoJumpPage = function () {
    var p = parseInt(document.getElementById('annoJumpInput').value);
    var totalPages = Math.ceil(annoState.dataset.length / annoState.pageSize);
    if (p > 0 && p <= totalPages) { annoState.page = p; renderAnnoCurrentPage(); window.scrollTo({ top: 0 }); }
  };

  // Card renderers
  function renderAnnoImageMultiCard(item, idx) {
    var tagsHtml = '';
    for (var t = 0; t < annoState.tags.length; t++) {
      var tag = annoState.tags[t];
      var selected = item.tags && item.tags.indexOf(tag) !== -1;
      tagsHtml += '<button class="anno-tag-btn' + (selected ? ' selected' : '') + '" onclick="window._annoToggleTag(' + idx + ',\'' + escapeHtmlAnno(tag) + '\')">' + escapeHtmlAnno(tag) + '</button>';
    }
    return '<div class="anno-data-card">' +
      '<img class="anno-card-img" src="' + escapeHtmlAnno(item.url) + '" data-src="' + escapeHtmlAnno(item.url) + '" onerror="this.src=\'data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22320%22 height=%22200%22%3E%3Crect fill=%22%23f0f0f0%22 width=%22320%22 height=%22200%22/%3E%3Ctext x=%2250%25%22 y=%2250%25%22 text-anchor=%22middle%22 fill=%22%23999%22%3E加载失败%3C/text%3E%3C/svg%3E\'">' +
      '<div class="anno-tag-btns">' + tagsHtml + '</div>' +
      '<span class="anno-badge">当前标签: ' + (item.tags && item.tags.length ? item.tags.join(', ') : '无') + '</span>' +
      '</div>';
  }

  function renderAnnoImageEvalCard(item, idx) {
    var isMatch = item.status === '符合';
    var isMismatch = item.status === '不符合';
    return '<div class="anno-data-card">' +
      '<img class="anno-card-img" src="' + escapeHtmlAnno(item.url) + '" data-src="' + escapeHtmlAnno(item.url) + '" onerror="this.src=\'data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22320%22 height=%22200%22%3E%3Crect fill=%22%23f0f0f0%22 width=%22320%22 height=%22200%22/%3E%3Ctext x=%2250%25%22 y=%2250%25%22 text-anchor=%22middle%22 fill=%22%23999%22%3E加载失败%3C/text%3E%3C/svg%3E\'">' +
      '<span class="anno-badge">机审标签: ' + escapeHtmlAnno(item.machineTag || '') + '</span>' +
      '<div class="anno-eval-btns">' +
        '<button class="anno-eval-btn' + (isMatch ? ' match' : '') + '" onclick="window._annoSetEval(' + idx + ',\'符合\')">符合</button>' +
        '<button class="anno-eval-btn' + (isMismatch ? ' mismatch' : '') + '" onclick="window._annoSetEval(' + idx + ',\'不符合\')">不符合</button>' +
      '</div>' +
      '<textarea class="anno-reason-textarea' + (item.status === '不符合' ? ' show' : '') + '" placeholder="不符合理由（选填）" oninput="window._annoUpdateReason(' + idx + ',this.value)">' + escapeHtmlAnno(item.reason || '') + '</textarea>' +
      '</div>';
  }

  function renderAnnoTextMultiCard(item, idx) {
    var tagsHtml = '';
    for (var t = 0; t < annoState.tags.length; t++) {
      var tag = annoState.tags[t];
      var selected = item.tags && item.tags.indexOf(tag) !== -1;
      tagsHtml += '<button class="anno-tag-btn' + (selected ? ' selected' : '') + '" onclick="window._annoToggleTag(' + idx + ',\'' + escapeHtmlAnno(tag) + '\')">' + escapeHtmlAnno(tag) + '</button>';
    }
    return '<div class="anno-data-card">' +
      '<div class="anno-card-title">' + escapeHtmlAnno(item.title || '无标题') + '</div>' +
      '<div class="anno-card-content">' + escapeHtmlAnno(item.content || '无内容') + '</div>' +
      '<div class="anno-tag-btns">' + tagsHtml + '</div>' +
      '<span class="anno-badge">已选: ' + (item.tags && item.tags.length ? item.tags.join(', ') : '未标注') + '</span>' +
      '</div>';
  }

  // Interaction functions
  window._annoToggleTag = function (idx, tag) {
    if (!annoState.dataset[idx]) return;
    var tagsArr = annoState.dataset[idx].tags;
    if (!tagsArr) tagsArr = annoState.dataset[idx].tags = [];
    var pos = tagsArr.indexOf(tag);
    if (pos !== -1) tagsArr.splice(pos, 1);
    else tagsArr.push(tag);
    renderAnnoCurrentPage();
  };
  window._annoSetEval = function (idx, status) {
    if (!annoState.dataset[idx]) return;
    annoState.dataset[idx].status = status;
    if (status === '符合') annoState.dataset[idx].reason = '';
    renderAnnoCurrentPage();
  };
  window._annoUpdateReason = function (idx, val) {
    if (annoState.dataset[idx]) annoState.dataset[idx].reason = val;
  };

  function escapeHtmlAnno(str) {
    if (!str && str !== 0) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // Import area rendering
  function renderAnnoImportArea() {
    var area = document.getElementById('annoImportArea');
    if (!area) return;
    if (annoState.mode === 'imageMulti') {
      area.innerHTML = '<textarea id="annoUrlInput" rows="3" placeholder="每行一个图片URL&#10;https://example.com/img1.jpg&#10;https://example.com/img2.png"></textarea>' +
        '<div class="form-actions"><button class="btn btn-primary btn-sm" id="annoLoadUrlBtn">加载图片</button></div>';
      var loadBtn = document.getElementById('annoLoadUrlBtn');
      if (loadBtn) loadBtn.addEventListener('click', function () {
        var urls = document.getElementById('annoUrlInput').value.split('\n').map(function (l) { return l.trim(); }).filter(function (l) { return l; });
        annoState.dataset = urls.map(function (url) { return { url: url, tags: [] }; });
        annoState.page = 1;
        renderAnnoCurrentPage();
      });
    } else if (annoState.mode === 'imageEval') {
      area.innerHTML = '<textarea id="annoEvalInput" rows="4" placeholder="格式: 图片URL,机审标签&#10;https://example.com/1.jpg,涉政&#10;https://example.com/2.jpg,色情"></textarea>' +
        '<div class="form-actions"><button class="btn btn-primary btn-sm" id="annoLoadEvalBtn">加载评估数据</button></div>';
      var evalBtn = document.getElementById('annoLoadEvalBtn');
      if (evalBtn) evalBtn.addEventListener('click', function () {
        var lines = document.getElementById('annoEvalInput').value.split('\n');
        annoState.dataset = [];
        lines.forEach(function (line) {
          var parts = line.split(',').map(function (s) { return s.trim(); });
          if (parts[0]) annoState.dataset.push({ url: parts[0], machineTag: parts[1] || '未知', status: '', reason: '' });
        });
        annoState.page = 1;
        renderAnnoCurrentPage();
      });
    } else if (annoState.mode === 'textMulti') {
      area.innerHTML = '<div class="file-upload-wrap">' +
        '<input type="file" id="annoTextXlsxFile" accept=".xlsx,.xls" class="file-input">' +
        '<label for="annoTextXlsxFile" class="file-label">选择 Excel 文件</label>' +
        '<span class="file-hint">Excel第一列新闻标题，第二列评论内容</span>' +
        '</div>';
      document.getElementById('annoTextXlsxFile').addEventListener('change', function (e) {
        var file = e.target.files[0];
        if (!file) return;
        var reader = new FileReader();
        reader.onload = function (evt) {
          var data = new Uint8Array(evt.target.result);
          var workbook = XLSX.read(data, { type: 'array' });
          var sheet = workbook.Sheets[workbook.SheetNames[0]];
          var rows = XLSX.utils.sheet_to_json(sheet, { header: 1 });
          if (rows.length < 2) return;
          annoState.dataset = rows.slice(1).filter(function (r) { return r[0] && r[1]; }).map(function (r) {
            return { title: String(r[0]), content: String(r[1]), tags: [] };
          });
          annoState.page = 1;
          renderAnnoCurrentPage();
        };
        reader.readAsArrayBuffer(file);
      });
    }
  }

  function switchAnnoMode(mode) {
    annoState.mode = mode;
    annoState.dataset = [];
    annoState.page = 1;

    // Update page title and description per mode
    var titles = { imageMulti: '图片分类标注', imageEval: '图片合规评估', textMulti: '文本评论标注' };
    var descs = {
      imageMulti: '对图片进行多标签分类标注，支持自定义标签库管理',
      imageEval: '对图片机审结果进行符合/不符合评估，支持填写不符合理由',
      textMulti: '对文本评论进行多标签分类标注，支持 Excel 批量导入'
    };
    var titleEl = document.getElementById('annoPageTitle');
    var descEl = document.getElementById('annoPageDesc');
    if (titleEl) titleEl.textContent = titles[mode] || mode;
    if (descEl) descEl.textContent = descs[mode] || '';

    // Toggle tag manager visibility
    var tagMgr = document.getElementById('annoTagManager');
    if (tagMgr) tagMgr.style.display = (mode === 'imageMulti' || mode === 'textMulti') ? 'block' : 'none';

    renderAnnoCurrentPage();
    renderAnnoImportArea();
    updateAnnoStatus();
  }

  // Export
  function exportAnnoData() {
    if (!annoState.dataset.length) { alert('无数据可导出'); return; }
    var rows, filename;
    if (annoState.mode === 'imageMulti') {
      rows = [['图片URL', '标注标签']];
      annoState.dataset.forEach(function (item) { rows.push([item.url, (item.tags || []).join(';')]); });
      filename = '图片分类标注.csv';
      downloadAnnoCSV(rows, filename);
    } else if (annoState.mode === 'imageEval') {
      rows = [['图片URL', '机审标签', '审核状态', '不符合理由']];
      annoState.dataset.forEach(function (item) { rows.push([item.url, item.machineTag || '', item.status || '', item.reason || '']); });
      filename = '图片合规评估.csv';
      downloadAnnoCSV(rows, filename);
    } else if (annoState.mode === 'textMulti') {
      rows = [['新闻标题', '评论内容', '标注标签']];
      annoState.dataset.forEach(function (item) { rows.push([item.title, item.content, (item.tags || []).join(';')]); });
      filename = '文本标注结果.xlsx';
      downloadAnnoXLSX(rows, filename);
    }
  }

  function downloadAnnoCSV(rows, filename) {
    var csv = rows.map(function (r) { return r.map(function (cell) { return '"' + String(cell).replace(/"/g, '""') + '"'; }).join(','); }).join('\n');
    var blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  function downloadAnnoXLSX(data, filename) {
    var ws = XLSX.utils.aoa_to_sheet(data);
    var wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Sheet1');
    XLSX.writeFile(wb, filename);
  }

  function clearAnnoData() {
    if (!confirm('清空当前所有标注数据？不可撤销')) return;
    annoState.dataset = [];
    annoState.page = 1;
    renderAnnoCurrentPage();
    updateAnnoStatus();
  }

  // ── Event Delegation ───────────────────────────────────────────
  function setupEventDelegation() {
    // Sidebar menu clicks — handle both parent and sub-menu items
    document.querySelector('.sidebar-menu').addEventListener('click', function (e) {
      var subItem = e.target.closest('.menu-sub-item');
      if (subItem) {
        switchMenu(subItem.dataset.menu);
        return;
      }
      var parentItem = e.target.closest('.menu-parent');
      if (parentItem) {
        // In collapsed mode, clicking parent opens the submenu dropdown
        var sidebar = document.getElementById('sidebar');
        if (sidebar && sidebar.classList.contains('collapsed')) return; // hover handles it

        // Accordion: only one sub-menu open at a time; clicking an open one closes it
        var isOpen = !parentItem.classList.contains('collapsed');
        if (isOpen) {
          parentItem.classList.add('collapsed');
          parentItem.nextElementSibling.style.display = 'none';
        } else {
          document.querySelectorAll('.menu-parent').forEach(function (el) {
            el.classList.add('collapsed');
            if (el.nextElementSibling && el.nextElementSibling.classList.contains('menu-sub-items')) {
              el.nextElementSibling.style.display = 'none';
            }
          });
          parentItem.classList.remove('collapsed');
          parentItem.nextElementSibling.style.display = '';
        }
        return;
      }
      var topItem = e.target.closest('.menu-item');
      if (topItem && !topItem.classList.contains('menu-parent')) {
        switchMenu(topItem.dataset.menu);
        return;
      }
    });

    // Sidebar collapse/expand toggle
    document.getElementById('sidebarToggle').addEventListener('click', function () {
      var sidebar = document.getElementById('sidebar');
      var collapsed = sidebar.classList.toggle('collapsed');
      localStorage.setItem('sidebar_collapsed', collapsed ? '1' : '0');
    });

    // Restore sidebar state
    (function () {
      if (localStorage.getItem('sidebar_collapsed') === '1') {
        document.getElementById('sidebar').classList.add('collapsed');
      }
    })();

    // Detect form submit
    document.getElementById('detectForm').addEventListener('submit', handleDetectSubmit);

    // Reset button
    document.getElementById('btnReset').addEventListener('click', resetForm);

    // Content type switcher
    document.getElementById('contentTypeSwitcher').addEventListener('click', function (e) {
      var btn = e.target.closest('.ct-btn');
      if (!btn) return;
      setContentType(btn.dataset.ct);
    });

    // Text char count
    document.getElementById('textContent').addEventListener('input', function () {
      document.getElementById('textCharCount').textContent = this.value.length + ' / 10000';
    });

    // Image file upload
    document.getElementById('imageFile').addEventListener('change', function () {
      var file = this.files[0];
      var errorEl = document.getElementById('imageError');
      var previewWrap = document.getElementById('imagePreview');
      errorEl.textContent = '';

      if (!file) {
        previewWrap.style.display = 'none';
        return;
      }

      var error = validateFile(file, 'image');
      if (error) {
        errorEl.textContent = error;
        this.value = '';
        previewWrap.style.display = 'none';
        return;
      }

      var url = URL.createObjectURL(file);
      document.getElementById('imagePreviewImg').src = url;
      previewWrap.style.display = 'inline-block';
    });

    document.getElementById('removeImage').addEventListener('click', function () {
      document.getElementById('imageFile').value = '';
      document.getElementById('imagePreview').style.display = 'none';
      document.getElementById('imageError').textContent = '';
    });

    // Video file upload
    document.getElementById('videoFile').addEventListener('change', function () {
      var file = this.files[0];
      var errorEl = document.getElementById('videoError');
      var previewWrap = document.getElementById('videoPreview');

      if (!file) {
        previewWrap.style.display = 'none';
        return;
      }

      var error = validateFile(file, 'video');
      if (error) {
        errorEl.textContent = error;
        this.value = '';
        previewWrap.style.display = 'none';
        return;
      }

      var url = URL.createObjectURL(file);
      document.getElementById('videoPreviewEl').src = url;
      previewWrap.style.display = 'inline-block';
    });

    document.getElementById('removeVideo').addEventListener('click', function () {
      document.getElementById('videoFile').value = '';
      document.getElementById('videoPreview').style.display = 'none';
      document.getElementById('videoError').textContent = '';
    });

    // Rule table actions (event delegation)
    document.getElementById('ruleTableBody').addEventListener('click', function (e) {
      var toggleBtn = e.target.closest('[data-toggle-rule]');
      if (toggleBtn) { toggleRule(toggleBtn.dataset.toggleRule); return; }
      var editBtn = e.target.closest('[data-edit-rule]');
      if (editBtn) { openRuleModal(editBtn.dataset.editRule); return; }
      var deleteBtn = e.target.closest('[data-delete-rule]');
      if (deleteBtn) { deleteRule(deleteBtn.dataset.deleteRule); return; }
    });

    // Rule modal
    document.getElementById('btnAddRule').addEventListener('click', function () { openRuleModal(null); });
    document.getElementById('ruleForm').addEventListener('submit', handleRuleFormSubmit);
    document.getElementById('btnRuleCancel').addEventListener('click', closeRuleModal);
    document.getElementById('btnRuleModalClose').addEventListener('click', closeRuleModal);

    // Close modals on overlay click
    document.getElementById('ruleModal').addEventListener('click', function (e) { if (e.target === this) closeRuleModal(); });
    document.getElementById('historyModal').addEventListener('click', function (e) { if (e.target === this) closeHistoryModal(); });

    // Rule filters
    document.getElementById('ruleSearch').addEventListener('input', renderRuleTable);
    document.getElementById('filterLabel').addEventListener('change', renderRuleTable);
    document.getElementById('filterRiskLevel').addEventListener('change', renderRuleTable);

    // History table actions
    document.getElementById('historyTableBody').addEventListener('click', function (e) {
      var viewBtn = e.target.closest('[data-view-history]');
      if (viewBtn) { viewHistoryDetail(viewBtn.dataset.viewHistory); }
    });
    document.getElementById('btnHistoryModalClose').addEventListener('click', closeHistoryModal);

    // Clear history
    document.getElementById('btnClearHistory').addEventListener('click', function () {
      if (!confirm('确定要清空所有检测记录吗？此操作不可恢复。')) return;
      history = [];
      saveHistory();
      renderHistoryTable();
      updateDashboard();
    });

    // ── Model Config page ──────────────────────────────────────────
    document.getElementById('btnNewModelConfig').addEventListener('click', function () { openModelConfigEdit(null); });

    // Model config table actions
    document.getElementById('modelConfigTableBody').addEventListener('click', function (e) {
      var editBtn = e.target.closest('[data-edit-model]');
      if (editBtn) { openModelConfigEdit(editBtn.dataset.editModel); return; }
      var deleteBtn = e.target.closest('[data-delete-model]');
      if (deleteBtn) { handleDeleteModelConfig(deleteBtn.dataset.deleteModel); return; }
      // Status toggle via checkbox change
      if (e.target.classList.contains('mc-status-toggle')) {
        handleToggleModelConfig(e.target.dataset.toggleModel);
        return;
      }
    });

    // Model config filter
    document.getElementById('filterModelStatus').addEventListener('change', renderModelConfigList);

    // Model config edit page
    document.getElementById('modelConfigForm').addEventListener('submit', handleSaveModelConfig);
    document.getElementById('btnMcmBack').addEventListener('click', backToModelConfigList);
    document.getElementById('btnMcmSaveApiKey').addEventListener('click', handleModelApiKeySave);
    document.getElementById('btnMcmDeleteApiKey').addEventListener('click', handleModelApiKeyDelete);
    document.getElementById('btnMcmToggleApiKey').addEventListener('click', handleModelApiKeyToggle);

    // ── Prompt Config page ─────────────────────────────────────────
    document.getElementById('btnNewPrompt').addEventListener('click', function () { openPromptEdit(null); });

    // Prompt table actions
    document.getElementById('promptTableBody').addEventListener('click', function (e) {
      var editBtn = e.target.closest('[data-edit-prompt]');
      if (editBtn) { openPromptEdit(editBtn.dataset.editPrompt); return; }
      var deleteBtn = e.target.closest('[data-delete-prompt]');
      if (deleteBtn) { handleDeletePrompt(deleteBtn.dataset.deletePrompt); return; }
    });

    // Prompt filter
    document.getElementById('filterPromptStatus').addEventListener('change', renderPromptList);

    // Prompt edit page
    document.getElementById('promptForm').addEventListener('submit', handleSavePrompt);
    document.getElementById('btnPmBack').addEventListener('click', backToPromptList);
    document.getElementById('pmSystemPrompt').addEventListener('blur', renderPromptVarTags);
    document.getElementById('pmUserPrompt').addEventListener('blur', renderPromptVarTags);

    // Parse field tag editor - double-click to edit, blur/enter/esc to save
    document.getElementById('pfTagEditor').addEventListener('dblclick', function (e) {
      var textEl = e.target.closest('.pf-tag-text');
      if (!textEl) return;
      var tag = textEl.closest('.pf-tag');
      if (tag) enterTagEditMode(tag);
    });
    document.getElementById('pfTagEditor').addEventListener('blur', function (e) {
      var inputEl = e.target.closest('.pf-tag-input');
      if (!inputEl) return;
      var tag = inputEl.closest('.pf-tag');
      if (tag) exitTagEditMode(tag);
    }, true);
    document.getElementById('pfTagEditor').addEventListener('keydown', function (e) {
      var inputEl = e.target.closest('.pf-tag-input');
      if (!inputEl) return;
      var tag = inputEl.closest('.pf-tag');
      if (!tag) return;
      if (e.key === 'Enter') { e.preventDefault(); exitTagEditMode(tag); }
      if (e.key === 'Escape') { var textEl = tag.querySelector('.pf-tag-text'); if (textEl) { inputEl.value = textEl.textContent; } exitTagEditMode(tag); }
    });

    // ── Single Test page ───────────────────────────────────────────
    document.getElementById('btnSingleTest').addEventListener('click', handleSingleTest);
    document.getElementById('stPromptTemplate').addEventListener('change', function () {
      renderSingleTestVarFields(this.value);
    });
    document.getElementById('stModelCategory').addEventListener('change', function () {
      populateCascadingModelSelect('stModelCategory', 'stModelConfig');
    });

    // Content type tabs
    document.querySelectorAll('.ct-tab').forEach(function (tab) {
      tab.addEventListener('click', function () {
        var ct = this.getAttribute('data-ct');
        document.querySelectorAll('.ct-tab').forEach(function (t) { t.classList.remove('active'); });
        document.querySelectorAll('.ct-panel').forEach(function (p) { p.classList.remove('active'); });
        this.classList.add('active');
        var panel = document.getElementById('ct-panel-' + ct);
        if (panel) panel.classList.add('active');
        // Hide previous test result when switching content type
        document.getElementById('stTestResult').style.display = 'none';
        document.getElementById('stTestStatusText').textContent = '';
      });
    });

    // Batch import/export placeholders
    document.getElementById('btnBatchImport').addEventListener('click', function () {
      alert('批量导入功能将在后续版本中实现');
    });
    document.getElementById('btnBatchExport').addEventListener('click', function () {
      if (rules.length === 0) { alert('暂无规则可导出'); return; }
      var json = JSON.stringify(rules, null, 2);
      var blob = new Blob([json], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'content_detection_rules.json';
      a.click();
      URL.revokeObjectURL(url);
    });

    // ── Batch Test page ──────────────────────────────────────────────
    document.getElementById('batchTaskForm').addEventListener('submit', handleCreateBatchTask);

    // ── Annotation Workbench events ─────────────────────────────────
    // Tag management
    document.getElementById('annoAddTagBtn').addEventListener('click', addAnnoTags);
    document.getElementById('annoClearAllTagsBtn').addEventListener('click', clearAnnoTags);
    document.getElementById('annoNewTagInput').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); addAnnoTags(); }
    });

    // Export & clear
    document.getElementById('annoExportBtn').addEventListener('click', exportAnnoData);
    document.getElementById('annoClearDataBtn').addEventListener('click', clearAnnoData);

    // Image modal click-outside
    document.getElementById('annoImageModal').addEventListener('click', function (e) {
      if (e.target === this) this.style.display = 'none';
    });
    document.getElementById('btnBtBack').addEventListener('click', backToBatchList);
    document.getElementById('btnDownloadTemplate').addEventListener('click', downloadBatchTemplate);

    // Sub-tabs: 创建任务 / 任务列表
    document.getElementById('btSubTabs').addEventListener('click', function (e) {
      var tab = e.target.closest('[data-bt-tab]');
      if (!tab) return;
      document.querySelectorAll('#btSubTabs .ct-tab').forEach(function (t) { t.classList.remove('active'); });
      tab.classList.add('active');
      document.querySelectorAll('.bt-panel').forEach(function (p) { p.classList.remove('active'); });
      var panel = document.getElementById('bt-panel-' + tab.getAttribute('data-bt-tab'));
      if (panel) panel.classList.add('active');
      if (tab.getAttribute('data-bt-tab') === 'list') {
        renderBatchTaskList();
        renderBatchProgress();
      }
    });

    // Prompt template change -> update template hint & show upload
    document.getElementById('btPromptTemplate').addEventListener('change', function () {
      updateBatchUploadSection(this.value);
      updateBatchTemplateHint();
    });
    document.getElementById('btModelCategory').addEventListener('change', function () {
      populateCascadingModelSelect('btModelCategory', 'btModelConfig');
    });

    // File upload
    document.getElementById('btFileInput').addEventListener('change', function () {
      if (this.files && this.files[0]) handleBatchFileUpload(this.files[0]);
    });
    var uploadZone = document.getElementById('btUploadZone');
    uploadZone.addEventListener('click', function () { document.getElementById('btFileInput').click(); });
    uploadZone.addEventListener('dragover', function (e) { e.preventDefault(); this.classList.add('drag-over'); });
    uploadZone.addEventListener('dragleave', function () { this.classList.remove('drag-over'); });
    uploadZone.addEventListener('drop', function (e) { e.preventDefault(); this.classList.remove('drag-over'); if (e.dataTransfer.files[0]) handleBatchFileUpload(e.dataTransfer.files[0]); });

    // Task list action delegation
    document.getElementById('batchTaskTableBody').addEventListener('click', function (e) {
      var detailBtn = e.target.closest('[data-batch-detail]');
      if (detailBtn) { openBatchDetail(detailBtn.getAttribute('data-batch-detail')); return; }
      var pauseBtn = e.target.closest('[data-batch-pause]');
      if (pauseBtn) { pauseBatchTask(pauseBtn.getAttribute('data-batch-pause')); return; }
      var resumeBtn = e.target.closest('[data-batch-resume]');
      if (resumeBtn) { resumeBatchTask(resumeBtn.getAttribute('data-batch-resume')); return; }
      var cancelBtn = e.target.closest('[data-batch-cancel]');
      if (cancelBtn) { cancelBatchTask(cancelBtn.getAttribute('data-batch-cancel')); return; }
      var exportBtn = e.target.closest('[data-batch-export]');
      if (exportBtn) { exportBatchResults(exportBtn.getAttribute('data-batch-export')); return; }
      var deleteBtn = e.target.closest('[data-batch-delete]');
      if (deleteBtn) { handleDeleteBatchTask(deleteBtn.getAttribute('data-batch-delete')); return; }
    });

    // Progress card action delegation
    document.getElementById('btProgressActions').addEventListener('click', function (e) {
      var pauseBtn = e.target.closest('[data-batch-pause]');
      if (pauseBtn) { pauseBatchTask(pauseBtn.getAttribute('data-batch-pause')); return; }
      var resumeBtn = e.target.closest('[data-batch-resume]');
      if (resumeBtn) { resumeBatchTask(resumeBtn.getAttribute('data-batch-resume')); return; }
      var cancelBtn = e.target.closest('[data-batch-cancel]');
      if (cancelBtn) { cancelBatchTask(cancelBtn.getAttribute('data-batch-cancel')); return; }
    });

    // Detail page action delegation
    document.getElementById('btDetailActions').addEventListener('click', function (e) {
      var pauseBtn = e.target.closest('[data-batch-pause]');
      if (pauseBtn) { pauseBatchTask(pauseBtn.getAttribute('data-batch-pause')); return; }
      var resumeBtn = e.target.closest('[data-batch-resume]');
      if (resumeBtn) { resumeBatchTask(resumeBtn.getAttribute('data-batch-resume')); return; }
      var cancelBtn = e.target.closest('[data-batch-cancel]');
      if (cancelBtn) { cancelBatchTask(cancelBtn.getAttribute('data-batch-cancel')); return; }
      var exportBtn = e.target.closest('[data-batch-export]');
      if (exportBtn) { exportBatchResults(exportBtn.getAttribute('data-batch-export')); return; }
      var deleteBtn = e.target.closest('[data-batch-delete]');
      if (deleteBtn) { handleDeleteBatchTask(deleteBtn.getAttribute('data-batch-delete')); return; }
    });

    // Detail content: item detail & pagination
    document.getElementById('btDetailContent').addEventListener('click', function (e) {
      var itemBtn = e.target.closest('[data-batch-item-detail]');
      if (itemBtn) {
        var parts = itemBtn.getAttribute('data-batch-item-detail').split('|');
        openBatchItemModal(parts[0], parts[1]);
        return;
      }
    });

    // Batch item modal close
    document.getElementById('batchItemModal').addEventListener('click', function (e) {
      if (e.target === this) this.style.display = 'none';
    });
    document.getElementById('btnBatchItemModalClose').addEventListener('click', function () {
      document.getElementById('batchItemModal').style.display = 'none';
    });

    // Filter changes
    document.getElementById('filterBtStatus').addEventListener('change', renderBatchTaskList);
    document.getElementById('filterBtSearch').addEventListener('input', function () {
      renderBatchTaskList();
    });
  }

  // ── Init ───────────────────────────────────────────────────────
  function initApp() {
    loadRules();
    loadHistory();
    loadModelConfigs();
    loadPromptTemplates();
    loadBatchTasks();
    updateContentTypeUI();
    renderRuleTable();
    renderHistoryTable();
    renderModelConfigList();
    renderPromptList();
    updateDashboard();
    loadAnnoTags();
    renderAnnoTagList();
    setupEventDelegation();

    // Init default timestamps for built-in rules if missing
    var rulesUpdated = false;
    var nowStr = now();
    rules.forEach(function (rule) {
      if (!rule.createdAt) { rule.createdAt = nowStr; rulesUpdated = true; }
      if (!rule.updatedAt) { rule.updatedAt = nowStr; rulesUpdated = true; }
    });
    if (rulesUpdated) { saveRules(); }
  }

  // ── Bootstrap ──────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', initApp);
})();
