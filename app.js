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
  const STORAGE_SAMPLE_LIBRARY = 'content_detection_sample_library';
  const STORAGE_SAMPLE_TAGS = 'content_detection_sample_tags';
  const STORAGE_SAMPLE_DATASETS = 'content_detection_sample_datasets';
  const STORAGE_SAMPLE_KNOWLEDGE = 'content_detection_sample_knowledge';
  const STORAGE_LABEL_RULES = 'content_detection_label_rules';
  const STORAGE_LABEL_CASES = 'content_detection_label_cases';
  const STORAGE_LABEL_VERSIONS = 'content_detection_label_versions';

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

  var DEFAULT_SAMPLE_TAGS = [
    { id: 'stag_1', name: '涉政', code: 'POLITICAL', level: 1, parentId: null, path: '涉政', description: '涉及政治敏感、政策攻击、政治人物、政治事件等内容', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'high', status: 'active', ownerId: null, sortOrder: 1 },
    { id: 'stag_2', name: '色情', code: 'PORN', level: 1, parentId: null, path: '色情', description: '明确色情、性交易、淫秽低俗内容', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'high', status: 'active', ownerId: null, sortOrder: 2 },
    { id: 'stag_3', name: '谩骂', code: 'ABUSE', level: 1, parentId: null, path: '谩骂', description: '侮辱、攻击、歧视、辱骂等内容', applicableContentTypes: ['text'], suggestedStatus: 'reject', riskLevel: 'medium', status: 'active', ownerId: null, sortOrder: 3 },
    { id: 'stag_4', name: '广告', code: 'AD', level: 1, parentId: null, path: '广告', description: '营销推广、站外引流、刷量刷单等内容', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'medium', status: 'active', ownerId: null, sortOrder: 4 },
    { id: 'stag_5', name: '违禁', code: 'ILLEGAL', level: 1, parentId: null, path: '违禁', description: '违法违禁品、管制物、黑灰产服务等内容', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'high', status: 'active', ownerId: null, sortOrder: 5 },
    { id: 'stag_6', name: '暴恐', code: 'VIOLENCE', level: 1, parentId: null, path: '暴恐', description: '暴力、恐怖主义、极端组织、血腥恐吓等内容', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'high', status: 'active', ownerId: null, sortOrder: 6 },
    { id: 'stag_7', name: '未成年', code: 'MINOR', level: 1, parentId: null, path: '未成年', description: '涉及未成年人不良内容、未成年保护等问题', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'high', status: 'active', ownerId: null, sortOrder: 7 },
    { id: 'stag_8', name: '灌水', code: 'SPAM', level: 1, parentId: null, path: '灌水', description: '无意义重复内容、刷屏、恶意灌水', applicableContentTypes: ['text'], suggestedStatus: 'suspect', riskLevel: 'low', status: 'active', ownerId: null, sortOrder: 8 },
    { id: 'stag_9', name: '其他', code: 'OTHER', level: 1, parentId: null, path: '其他', description: '其他需要关注的违规或异常内容', applicableContentTypes: ['text','image'], suggestedStatus: 'suspect', riskLevel: 'low', status: 'active', ownerId: null, sortOrder: 9 }
  ];

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
  let sampleLibrary = [];
  let sampleTags = [];
  let sampleDatasets = [];
  let sampleKnowledge = [];
  let currentSampleId = null;
  let slExpandedTagIds = {};
  let slExpandedL3CardId = null;  // currently expanded L3 card in accordion (only one at a time)
  let slListPage = 1;
  let slListFilter = {};
  let labelRules = [];
  let labelCases = [];
  let labelVersions = [];
  let currentRuleTagId = null;     // currently selected level-3 tag for rule editing
  let currentRuleTab = 'basic';    // active tab in rule workspace
  let currentRuleContentType = 'text'; // active sub-tab in rule settings

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

  function loadSampleLibrary() {
    try { var raw = localStorage.getItem(STORAGE_SAMPLE_LIBRARY); if (raw) { sampleLibrary = JSON.parse(raw); return; } } catch (e) {}
    sampleLibrary = [];
  }
  function saveSampleLibrary() { localStorage.setItem(STORAGE_SAMPLE_LIBRARY, JSON.stringify(sampleLibrary)); }

  function loadSampleTags() {
    try { var raw = localStorage.getItem(STORAGE_SAMPLE_TAGS); if (raw) { sampleTags = JSON.parse(raw); } else { sampleTags = []; } } catch (e) { sampleTags = []; }
    var migrated = false;
    sampleTags.forEach(function (t) {
      // Legacy field migrations
      if (!t.hitConditions) { t.hitConditions = []; migrated = true; }
      if (!t.excludeConditions) { t.excludeConditions = []; migrated = true; }
      if (typeof t.positiveExamples === 'string') { t.positiveExamples = t.positiveExamples.split('\n').filter(function (s) { return s.trim(); }); migrated = true; }
      if (typeof t.negativeExamples === 'string') { t.negativeExamples = t.negativeExamples.split('\n').filter(function (s) { return s.trim(); }); migrated = true; }
      // New field migrations
      if (!t.code) { t.code = t.name; migrated = true; }
      if (!t.path) { t.path = t.name; migrated = true; }
      if (!t.applicableContentTypes) { t.applicableContentTypes = (t.applicableType === 'all' || !t.applicableType) ? ['text','image'] : [t.applicableType]; migrated = true; }
      if (!t.suggestedStatus) { t.suggestedStatus = 'reject'; migrated = true; }
      if (!t.riskLevel) { t.riskLevel = 'medium'; migrated = true; }
      if (t.status === 'enabled') { t.status = 'active'; migrated = true; }
      if (t.status === 'disabled') { t.status = 'disabled'; migrated = true; }
      if (!t.ownerId) { t.ownerId = null; migrated = true; }
    });
    if (sampleTags.length === 0) {
      var nowStr = now();
      sampleTags = DEFAULT_SAMPLE_TAGS.map(function (t) { t.createdAt = nowStr; t.updatedAt = nowStr; return t; });
    }
    // Seed level-2/3 tags if none exist
    var hasLvl2 = sampleTags.filter(function (t) { return t.level > 1; }).length > 0;
    if (!hasLvl2) { seedLevel23Tags(now()); migrated = true; }
    if (migrated) saveSampleTags();
  }
  function saveSampleTags() { localStorage.setItem(STORAGE_SAMPLE_TAGS, JSON.stringify(sampleTags)); }

  // Seed level-2 and level-3 tags under level-1 categories
  function seedLevel23Tags(nowStr) {
    var seed = [
      // 广告 sub-tags
      { id: 'stag_4_1', name: '站外引流', code: 'AD_OFFSITE', level: 2, parentId: 'stag_4', path: '广告/站外引流', description: '引导用户至站外平台', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'medium', status: 'active', ownerId: null, sortOrder: 1, createdAt: nowStr, updatedAt: nowStr },
      { id: 'stag_4_1_1', name: '微信号引流', code: 'AD_OFFSITE_WECHAT', level: 3, parentId: 'stag_4_1', path: '广告/站外引流/微信号引流', description: '通过内容引导添加微信号、微信群等', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'medium', status: 'active', ownerId: null, sortOrder: 1, createdAt: nowStr, updatedAt: nowStr },
      { id: 'stag_4_1_2', name: 'QQ引流', code: 'AD_OFFSITE_QQ', level: 3, parentId: 'stag_4_1', path: '广告/站外引流/QQ引流', description: '引导添加QQ号、QQ群', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'medium', status: 'active', ownerId: null, sortOrder: 2, createdAt: nowStr, updatedAt: nowStr },
      { id: 'stag_4_2', name: '虚假宣传', code: 'AD_FALSE', level: 2, parentId: 'stag_4', path: '广告/虚假宣传', description: '夸大效果、虚假承诺等', applicableContentTypes: ['text'], suggestedStatus: 'reject', riskLevel: 'medium', status: 'active', ownerId: null, sortOrder: 2, createdAt: nowStr, updatedAt: nowStr },
      { id: 'stag_4_2_1', name: '效果夸大', code: 'AD_FALSE_EXAGGERATE', level: 3, parentId: 'stag_4_2', path: '广告/虚假宣传/效果夸大', description: '对产品效果进行明显夸大宣传', applicableContentTypes: ['text'], suggestedStatus: 'reject', riskLevel: 'medium', status: 'active', ownerId: null, sortOrder: 1, createdAt: nowStr, updatedAt: nowStr },
      // 色情 sub-tags
      { id: 'stag_2_1', name: '低俗内容', code: 'PORN_VULGAR', level: 2, parentId: 'stag_2', path: '色情/低俗内容', description: '虽未达到色情标准但低俗不雅', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'medium', status: 'active', ownerId: null, sortOrder: 1, createdAt: nowStr, updatedAt: nowStr },
      { id: 'stag_2_1_1', name: '性暗示', code: 'PORN_VULGAR_SUGGEST', level: 3, parentId: 'stag_2_1', path: '色情/低俗内容/性暗示', description: '含性暗示、暧昧挑逗内容', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'medium', status: 'active', ownerId: null, sortOrder: 1, createdAt: nowStr, updatedAt: nowStr },
      // 谩骂 sub-tags
      { id: 'stag_3_1', name: '人身攻击', code: 'ABUSE_PERSONAL', level: 2, parentId: 'stag_3', path: '谩骂/人身攻击', description: '直接针对个人的侮辱性言论', applicableContentTypes: ['text'], suggestedStatus: 'reject', riskLevel: 'high', status: 'active', ownerId: null, sortOrder: 1, createdAt: nowStr, updatedAt: nowStr },
      { id: 'stag_3_1_1', name: '辱骂诅咒', code: 'ABUSE_PERSONAL_CURSE', level: 3, parentId: 'stag_3_1', path: '谩骂/人身攻击/辱骂诅咒', description: '直接辱骂、人身诅咒、人身侮辱', applicableContentTypes: ['text'], suggestedStatus: 'reject', riskLevel: 'high', status: 'active', ownerId: null, sortOrder: 1, createdAt: nowStr, updatedAt: nowStr },
      // 暴恐 sub-tags
      { id: 'stag_6_1', name: '暴力内容', code: 'VIOLENCE_CONTENT', level: 2, parentId: 'stag_6', path: '暴恐/暴力内容', description: '暴力场景、血腥画面等内容', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'high', status: 'active', ownerId: null, sortOrder: 1, createdAt: nowStr, updatedAt: nowStr },
      { id: 'stag_6_1_1', name: '血腥暴力', code: 'VIOLENCE_CONTENT_BLOODY', level: 3, parentId: 'stag_6_1', path: '暴恐/暴力内容/血腥暴力', description: '血腥、残忍、暴力伤害场景', applicableContentTypes: ['text','image'], suggestedStatus: 'reject', riskLevel: 'high', status: 'active', ownerId: null, sortOrder: 1, createdAt: nowStr, updatedAt: nowStr },
    ];
    seed.forEach(function (t) {
      if (!sampleTags.filter(function (x) { return x.id === t.id; })[0]) {
        sampleTags.push(t);
      }
    });
    saveSampleTags();
  }

  // ── Label Rules ──────────────────────────────────────────────────
  function loadLabelRules() {
    try { var raw = localStorage.getItem(STORAGE_LABEL_RULES); if (raw) { labelRules = JSON.parse(raw); } else { labelRules = []; } } catch (e) { labelRules = []; }
    if (labelRules.length === 0) { seedLabelRules(); }
  }
  function saveLabelRules() { localStorage.setItem(STORAGE_LABEL_RULES, JSON.stringify(labelRules)); }
  function getLabelRule(labelId, contentType) {
    return labelRules.filter(function (r) { return r.labelId === labelId && r.contentType === contentType; })[0] || null;
  }
  function seedLabelRules() {
    var seedRules = [
      { id: 'rule_1', labelId: 'stag_4_1_1', contentType: 'text', ruleSummary: '检测文本中是否包含微信号引流行为，包括微信号、微信二维码、加微信等引导话术', keywords: ['微信', 'vx', '加V', '威信', 'WeChat'], semanticFeatures: '诱导用户添加个人微信进行站外沟通或交易', hitConditions: [{id:'hc1',field:'content',operator:'contains',value:'微信'},{id:'hc2',field:'content',operator:'regex',value:'[vVwW]\s*[xX]'}], excludeConditions: [{id:'ec1',field:'content',operator:'contains',value:'微信公众号'}], disposalSuggestion: 'reject', applicableScenes: ['评论','私信','个人简介'], version: 1, status: 'active', createdBy: null, createdAt: now(), updatedAt: now() },
      { id: 'rule_2', labelId: 'stag_4_1_2', contentType: 'text', ruleSummary: '检测文本中是否包含QQ引流行为', keywords: ['QQ', 'qq', '扣扣', '企鹅'], semanticFeatures: '诱导用户添加QQ号码或QQ群进行站外沟通', hitConditions: [{id:'hc3',field:'content',operator:'contains',value:'QQ'}], excludeConditions: [], disposalSuggestion: 'reject', applicableScenes: ['评论','私信'], version: 1, status: 'active', createdBy: null, createdAt: now(), updatedAt: now() },
      { id: 'rule_3', labelId: 'stag_2_1_1', contentType: 'text', ruleSummary: '检测文本擦边内容', keywords: ['诱惑', '暧昧', '约吗'], semanticFeatures: '性暗示、暧昧挑逗的文本内容', hitConditions: [{id:'hc4',field:'content',operator:'contains',value:'暧昧'}], excludeConditions: [], disposalSuggestion: 'reject', applicableScenes: ['评论','私信','动态'], version: 1, status: 'active', createdBy: null, createdAt: now(), updatedAt: now() },
      { id: 'rule_4', labelId: 'stag_3_1_1', contentType: 'text', ruleSummary: '检测辱骂诅咒类内容', keywords: ['傻逼', '脑残', '去死', 'nmsl'], semanticFeatures: '直接辱骂、诅咒、恶毒语言攻击', hitConditions: [{id:'hc5',field:'content',operator:'contains',value:'傻逼'}], excludeConditions: [{id:'ec2',field:'content',operator:'contains',value:'笑死'}], disposalSuggestion: 'reject', applicableScenes: ['评论'], version: 1, status: 'active', createdBy: null, createdAt: now(), updatedAt: now() },
    ];
    labelRules = seedRules;
    saveLabelRules();
  }

  // ── Label Cases ──────────────────────────────────────────────────
  function loadLabelCases() {
    try { var raw = localStorage.getItem(STORAGE_LABEL_CASES); if (raw) { labelCases = JSON.parse(raw); } else { labelCases = []; } } catch (e) { labelCases = []; }
    if (labelCases.length === 0) { seedLabelCases(); }
  }
  function saveLabelCases() { localStorage.setItem(STORAGE_LABEL_CASES, JSON.stringify(labelCases)); }
  function getLabelCases(labelId, caseType) {
    return labelCases.filter(function (c) { return c.labelId === labelId && (!caseType || c.caseType === caseType); });
  }
  function seedLabelCases() {
    var nowStr = now();
    labelCases = [
      { id: 'case_1', labelId: 'stag_4_1_1', caseType: 'positive', contentType: 'text', textContent: '加我微信 xxx123456 了解更多优惠', imageUrl: '', ocrText: '', judgmentStatus: 'reject', judgmentReason: '明确引导添加微信号，属于站外引流', keyEvidence: '微信号 xxx123456', scene: '评论', correctLabelId: null, canUseForTraining: true, canUseForRag: true, reviewStatus: 'confirmed', createdBy: null, createdAt: nowStr, updatedAt: nowStr },
      { id: 'case_2', labelId: 'stag_4_1_1', caseType: 'positive', contentType: 'text', textContent: 'VX: test888 详情私聊', imageUrl: '', ocrText: '', judgmentStatus: 'reject', judgmentReason: '使用VX缩写引导添加微信', keyEvidence: 'VX: test888', scene: '私信', correctLabelId: null, canUseForTraining: true, canUseForRag: true, reviewStatus: 'confirmed', createdBy: null, createdAt: nowStr, updatedAt: nowStr },
      { id: 'case_3', labelId: 'stag_4_1_1', caseType: 'negative', contentType: 'text', textContent: '关注我们的微信公众号获取更多资讯', imageUrl: '', ocrText: '', judgmentStatus: 'pass', judgmentReason: '引导关注微信公众号属于平台内正常行为，不应判为站外引流', keyEvidence: '微信公众号是平台内功能', scene: '评论', correctLabelId: null, canUseForTraining: true, canUseForRag: true, reviewStatus: 'confirmed', createdBy: null, createdAt: nowStr, updatedAt: nowStr },
      { id: 'case_4', labelId: 'stag_2_1_1', caseType: 'positive', contentType: 'text', textContent: '今晚有空吗，出来玩玩呀～各种姿势都可以哦', imageUrl: '', ocrText: '', judgmentStatus: 'reject', judgmentReason: '含明显性暗示和挑逗内容', keyEvidence: '各种姿势都可以', scene: '私信', correctLabelId: null, canUseForTraining: true, canUseForRag: true, reviewStatus: 'confirmed', createdBy: null, createdAt: nowStr, updatedAt: nowStr },
      { id: 'case_5', labelId: 'stag_3_1_1', caseType: 'positive', contentType: 'text', textContent: '你就是个傻逼，赶紧去死吧', imageUrl: '', ocrText: '', judgmentStatus: 'reject', judgmentReason: '直接辱骂并诅咒他人', keyEvidence: '傻逼、去死', scene: '评论', correctLabelId: null, canUseForTraining: true, canUseForRag: true, reviewStatus: 'confirmed', createdBy: null, createdAt: nowStr, updatedAt: nowStr },
    ];
    saveLabelCases();
  }

  // ── Label Versions ───────────────────────────────────────────────
  function loadLabelVersions() {
    try { var raw = localStorage.getItem(STORAGE_LABEL_VERSIONS); if (raw) { labelVersions = JSON.parse(raw); } else { labelVersions = []; } } catch (e) { labelVersions = []; }
  }
  function saveLabelVersions() { localStorage.setItem(STORAGE_LABEL_VERSIONS, JSON.stringify(labelVersions)); }

  function loadSampleDatasets() {
    try { var raw = localStorage.getItem(STORAGE_SAMPLE_DATASETS); if (raw) { sampleDatasets = JSON.parse(raw); return; } } catch (e) {}
    sampleDatasets = [];
  }
  function saveSampleDatasets() { localStorage.setItem(STORAGE_SAMPLE_DATASETS, JSON.stringify(sampleDatasets)); }

  function loadSampleKnowledge() {
    try { var raw = localStorage.getItem(STORAGE_SAMPLE_KNOWLEDGE); if (raw) { sampleKnowledge = JSON.parse(raw); return; } } catch (e) {}
    sampleKnowledge = [];
  }
  function saveSampleKnowledge() { localStorage.setItem(STORAGE_SAMPLE_KNOWLEDGE, JSON.stringify(sampleKnowledge)); }

  function getSampleById(id) { return sampleLibrary.filter(function (s) { return s.id === id; })[0]; }
  function getSampleTagById(id) { return sampleTags.filter(function (t) { return t.id === id; })[0]; }
  function isSampleTagEnabled(tag) { return !tag || tag.status !== 'disabled'; }
  function getSampleChildTags(parentId) {
    return sampleTags
      .filter(function (t) { return t.parentId === parentId && isSampleTagEnabled(t); })
      .sort(function (a, b) { return (a.sortOrder || 0) - (b.sortOrder || 0); });
  }
  function getSampleDescendantTagIds(tagId) {
    var ids = [];
    function walk(parentId) {
      sampleTags.forEach(function (tag) {
        if (tag.parentId === parentId) {
          ids.push(tag.id);
          walk(tag.id);
        }
      });
    }
    walk(tagId);
    return ids;
  }
  function getSampleTagSampleCount(tagId) {
    var relatedIds = [tagId].concat(getSampleDescendantTagIds(tagId));
    return sampleLibrary.filter(function (sample) {
      if (relatedIds.indexOf(sample.categoryId) !== -1) return true;
      return (sample.tagIds || []).some(function (id) { return relatedIds.indexOf(id) !== -1; });
    }).length;
  }
  function getSampleTagCaseCount(tagId) {
    var relatedIds = [tagId].concat(getSampleDescendantTagIds(tagId));
    return labelCases.filter(function (item) { return relatedIds.indexOf(item.labelId) !== -1; }).length;
  }
  function getSampleThirdLevelTagCount(tagId) {
    var tag = getSampleTagById(tagId);
    if (!tag || tag.level >= 3) return 0;
    var relatedIds = getSampleDescendantTagIds(tagId);
    return sampleTags.filter(function (item) {
      return item.level === 3 && relatedIds.indexOf(item.id) !== -1 && isSampleTagEnabled(item);
    }).length;
  }
  function updateSampleTagPath(tagId) {
    var tag = getSampleTagById(tagId);
    if (!tag) return;
    var parent = tag.parentId ? getSampleTagById(tag.parentId) : null;
    tag.level = parent ? parent.level + 1 : 1;
    tag.path = parent ? (parent.path || parent.name) + '/' + tag.name : tag.name;
    tag.updatedAt = now();
    sampleTags.forEach(function (child) {
      if (child.parentId === tag.id) updateSampleTagPath(child.id);
    });
  }
  function getSampleSiblingTags(tag) {
    return sampleTags
      .filter(function (item) { return (item.parentId || null) === (tag.parentId || null) && item.level === tag.level; })
      .sort(function (a, b) { return (a.sortOrder || 0) - (b.sortOrder || 0); });
  }
  function getSampleTagPath(tagId) {
    var path = [];
    var current = getSampleTagById(tagId);
    while (current) { path.unshift(current.name); current = current.parentId ? getSampleTagById(current.parentId) : null; }
    return path;
  }

  function initDemoSamples() {
    var nowStr = now();
    sampleLibrary = [
      {
        id: generateId('SAMP'),
        content: '这个产品真的太好了，强烈推荐给大家，加我微信xxx了解更多优惠信息。',
        contentType: 'text',
        status: 'reject',
        categoryId: 'stag_4',
        tagIds: ['stag_4'],
        source: '线上召回',
        usage: [],
        reviewReason: '包含微信号引流推广内容，属于广告违规',
        confidence: 95,
        auditHistory: [{ time: nowStr, action: '初始标注', detail: '状态: 不通过 | 分类: 广告', operator: '标注员A' }],
        createdAt: nowStr,
        updatedAt: nowStr
      },
      {
        id: generateId('SAMP'),
        content: '今天天气真好，适合出去走走，大家觉得呢？',
        contentType: 'text',
        status: 'pass',
        categoryId: 'stag_9',
        tagIds: ['stag_9'],
        source: '线上召回',
        usage: [],
        reviewReason: '正常社交交流内容，无违规风险',
        confidence: 98,
        auditHistory: [{ time: nowStr, action: '初始标注', detail: '状态: 通过 | 分类: 其他', operator: '标注员B' }],
        createdAt: nowStr,
        updatedAt: nowStr
      },
      {
        id: generateId('SAMP'),
        content: '这个政策简直就是胡闹，某领导人完全不懂民生！',
        contentType: 'text',
        status: 'suspect',
        categoryId: 'stag_1',
        tagIds: ['stag_1'],
        source: '用户反馈',
        usage: [],
        reviewReason: '有攻击政策倾向但需进一步确认是否达到违规标准',
        confidence: 60,
        auditHistory: [{ time: nowStr, action: '初始标注', detail: '状态: 嫌疑 | 分类: 涉政', operator: '标注员A' }],
        createdAt: nowStr,
        updatedAt: nowStr
      }
    ];
    saveSampleLibrary();
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
  function setMenuParentOpen(parentItem, open) {
    if (!parentItem) return;
    parentItem.classList.toggle('is-open', open);
    parentItem.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  function closeAllMenuParents(exceptItem) {
    document.querySelectorAll('.menu-parent').forEach(function (el) {
      if (el !== exceptItem) setMenuParentOpen(el, false);
    });
  }

  function openParentForSubMenu(menuName) {
    var subTarget = document.querySelector('.menu-sub-item[data-menu="' + menuName + '"]');
    if (!subTarget) return;
    var subItems = subTarget.closest('.menu-sub-items');
    var parentItem = subItems ? subItems.previousElementSibling : null;
    if (parentItem) {
      closeAllMenuParents(parentItem);
      setMenuParentOpen(parentItem, true);
    }
  }

  function setSidebarCollapsed(collapsed) {
    var sidebar = document.getElementById('sidebar');
    var toggle = document.getElementById('sidebarToggle');
    if (!sidebar) return;
    if (collapsed) closeAllMenuParents();
    sidebar.classList.toggle('is-collapsed', collapsed);
    if (toggle) toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    localStorage.setItem('sidebar_collapsed', collapsed ? '1' : '0');
  }

  function switchMenu(menuName) {
    document.querySelectorAll('.menu-sub-item').forEach(function (m) { m.classList.remove('active'); });
    var subTarget = document.querySelector('.menu-sub-item[data-menu="' + menuName + '"]');
    if (subTarget) {
      subTarget.classList.add('active');
      openParentForSubMenu(menuName);
    }

    document.querySelectorAll('.menu-item').forEach(function (m) { m.classList.remove('active'); });

    // Annotation sub-pages: all map to the unified annotation tab
    var annoModes = ['annotation-image-multi', 'annotation-image-eval'];
    var isAnnoPage = annoModes.indexOf(menuName) !== -1;
    var isCommentPage = menuName === 'annotation-comment';

    // Sample library sub-pages
    var isSampleSubPage = menuName && menuName.indexOf('sample-') === 0 && menuName !== 'sample-library';

    // Edit/detail sub-pages: highlight the parent menu item
    var isEditPage = menuName === 'model-config-edit' || menuName === 'prompt-config-edit' || menuName === 'batch-test-detail' || menuName === 'sample-detail';
    if (subTarget || isEditPage || isAnnoPage || isCommentPage || isSampleSubPage) {
      var parentMenu;
      if (isAnnoPage || isCommentPage) parentMenu = 'annotation';
      else if (isSampleSubPage || menuName === 'sample-detail') parentMenu = 'sample-library';
      else parentMenu = 'model';
      var parentItem = document.querySelector('.menu-parent[data-menu="' + parentMenu + '"]');
      if (parentItem) {
        parentItem.classList.add('active');
        closeAllMenuParents(parentItem);
        setMenuParentOpen(parentItem, true);
      }
      // Highlight the list sub-item matching the edit/detail page
      var listName = menuName;
      if (menuName === 'model-config-edit') listName = 'model-config';
      else if (menuName === 'prompt-config-edit') listName = 'prompt-config';
      else if (menuName === 'batch-test-detail') listName = 'batch-test';
      else if (menuName === 'sample-detail') listName = 'sample-list';
      if (isEditPage) {
        var listItem = document.querySelector('.menu-sub-item[data-menu="' + listName + '"]');
        if (listItem) listItem.classList.add('active');
      }
    } else {
      closeAllMenuParents();
      var topTarget = document.querySelector('.menu-item[data-menu="' + menuName + '"]');
      if (topTarget) topTarget.classList.add('active');
    }

    document.querySelectorAll('.tab-content').forEach(function (c) { c.classList.remove('active'); });

    // Annotation sub-items all go to the unified annotation tab
    var tabId;
    if (isAnnoPage) tabId = 'tab-annotation';
    else if (isCommentPage) tabId = 'tab-annotation-comment';
    else tabId = 'tab-' + menuName;
    var tabEl = document.getElementById(tabId);
    if (tabEl) tabEl.classList.add('active');

    if (isAnnoPage) {
      var modeMap = {
        'annotation-image-multi': 'imageMulti',
        'annotation-image-eval': 'imageEval',
      };
      switchAnnoMode(modeMap[menuName]);
    }

    if (isCommentPage) {
      initCommentLabeling();
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

    // Sample library page rendering
    if (menuName === 'sample-dashboard') { renderSampleTags(); }
    if (menuName === 'sample-list') { slListPage = 1; slListFilter = {}; renderSampleList(); }
    if (menuName === 'sample-tags') { switchMenu('sample-dashboard'); return; }
    if (menuName === 'sample-datasets') renderSampleDatasets();
    if (menuName === 'sample-knowledge') renderSampleKnowledge();
    if (menuName === 'sample-detail') renderSampleDetail(currentSampleId);
  }

  function backToBatchList() {
    currentBatchTaskId = null;
    switchMenu('batch-test');
    // 切换到任务列表子标签页
    document.querySelectorAll('#btSubTabs .ct-tab').forEach(function (t) { t.classList.remove('active'); });
    var listTab = document.querySelector('#btSubTabs .ct-tab[data-bt-tab="list"]');
    if (listTab) listTab.classList.add('active');
    document.querySelectorAll('.bt-panel').forEach(function (p) { p.classList.remove('active'); });
    var listPanel = document.getElementById('bt-panel-list');
    if (listPanel) listPanel.classList.add('active');
    renderBatchTaskList();
    renderBatchProgress();
  }

  // ══════════════════════════════════════════════════════════════════
  // Content Sample Library — Rendering Functions
  // ══════════════════════════════════════════════════════════════════

  function slStatusBadge(status) {
    var map = { pass: '通过', reject: '不通过', suspect: '嫌疑' };
    var cls = { pass: 'badge-pass', reject: 'badge-reject', suspect: 'badge-suspect' };
    return '<span class="badge ' + (cls[status] || '') + '">' + (map[status] || status) + '</span>';
  }

  function slDatasetTypeLabel(type) {
    var map = { training: '训练集', test: '测试集', validation: '验证集', hard_case: '难例集', regression: '回归集', rag: 'RAG候选集' };
    return map[type] || type;
  }

  function slSourceLabel(src) {
    var map = { manual: '人工导入', online_recall: '线上召回', model_miss: '模型误判', user_feedback: '用户反馈', red_team: '红队构造' };
    return map[src] || src;
  }

  function slKnowledgeStatusBadge(status) {
    var map = { draft: '草稿', published: '已发布', archived: '已归档' };
    var cls = { draft: 'badge-info', published: 'badge-pass', archived: 'badge-secondary' };
    return '<span class="badge ' + (cls[status] || '') + '">' + (map[status] || status) + '</span>';
  }

  function renderSlPagination(containerId, page, totalPages, onPageChange) {
    var container = document.getElementById(containerId);
    if (!container || totalPages <= 1) { if (container) container.innerHTML = ''; return; }
    var html = '';
    html += '<button' + (page <= 1 ? ' disabled' : '') + ' data-page="' + (page - 1) + '">上一页</button>';
    for (var i = 1; i <= totalPages; i++) {
      html += '<button' + (i === page ? ' class="active"' : '') + ' data-page="' + i + '">' + i + '</button>';
    }
    html += '<button' + (page >= totalPages ? ' disabled' : '') + ' data-page="' + (page + 1) + '">下一页</button>';
    html += '<span class="page-info">共 ' + totalPages + ' 页</span>';
    container.innerHTML = html;
    container.querySelectorAll('button[data-page]').forEach(function (btn) {
      btn.addEventListener('click', function () { onPageChange(parseInt(this.dataset.page)); });
    });
  }

  // ── Dashboard ────────────────────────────────────────────────────
  // Sample List ──────────────────────────────────────────────────
  function renderSampleList() {
    // Populate filter category dropdown
    var catSelect = document.getElementById('slFilterCategory');
    catSelect.innerHTML = '<option value="">全部分类</option>';
    var lvl1Tags = sampleTags.filter(function (t) { return t.level === 1 && isSampleTagEnabled(t); });
    lvl1Tags.forEach(function (t) {
      catSelect.innerHTML += '<option value="' + t.id + '">' + t.name + '</option>';
    });
    catSelect.value = slListFilter.categoryId || '';

    // Apply filters
    var filtered = sampleLibrary.slice();
    if (slListFilter.search) {
      var kw = slListFilter.search.toLowerCase();
      filtered = filtered.filter(function (s) {
        return (s.title && s.title.toLowerCase().indexOf(kw) !== -1) ||
               (s.content && s.content.toLowerCase().indexOf(kw) !== -1) ||
               (s.reviewReason && s.reviewReason.toLowerCase().indexOf(kw) !== -1);
      });
    }
    if (slListFilter.contentType) filtered = filtered.filter(function (s) { return s.contentType === slListFilter.contentType; });
    if (slListFilter.status) filtered = filtered.filter(function (s) { return s.status === slListFilter.status; });
    if (slListFilter.categoryId) filtered = filtered.filter(function (s) { return s.categoryId === slListFilter.categoryId; });

    // Sort by updatedAt descending
    filtered.sort(function (a, b) { return (b.updatedAt || '').localeCompare(a.updatedAt || ''); });

    var pageSize = 15;
    var totalPages = Math.ceil(filtered.length / pageSize) || 1;
    if (slListPage > totalPages) slListPage = totalPages;
    var start = (slListPage - 1) * pageSize;
    var pageItems = filtered.slice(start, start + pageSize);

    var tbody = document.getElementById('slSampleTableBody');
    if (pageItems.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="table-empty">暂无样本数据</td></tr>';
    } else {
      tbody.innerHTML = pageItems.map(function (s) {
        var tag = getSampleTagById(s.categoryId);
        var catName = tag ? tag.name : '-';
        var preview = '';
        if (s.contentType === 'text') {
          preview = (s.title || s.content || '').substring(0, 50) + ((s.content || '').length > 50 ? '...' : '');
        } else {
          preview = '<img src="' + (s.imageUrl || '') + '" style="width:48px;height:48px;object-fit:cover;border-radius:4px;" onerror="this.style.display=\'none\'">';
        }
        return '<tr>' +
          '<td><a class="link" data-action="sl-view" data-id="' + s.id + '" href="#">' + s.id + '</a></td>' +
          '<td>' + preview + '</td>' +
          '<td>' + contentTypeLabel(s.contentType) + '</td>' +
          '<td>' + slStatusBadge(s.status) + '</td>' +
          '<td>' + catName + '</td>' +
          '<td>' + slSourceLabel(s.source) + '</td>' +
          '<td>' + formatTime(s.updatedAt) + '</td>' +
          '<td>' +
            '<a class="link" data-action="sl-view" data-id="' + s.id + '" href="#">查看</a> ' +
            '<a class="link" data-action="sl-edit" data-id="' + s.id + '" href="#">编辑</a>' +
          '</td>' +
        '</tr>';
      }).join('');
    }

    document.getElementById('slSampleCount').textContent = '共 ' + filtered.length + ' 条';
    renderSlPagination('slListPagination', slListPage, totalPages, function (p) {
      slListPage = p;
      renderSampleList();
    });
  }

  // ── Sample Detail ────────────────────────────────────────────────
  function renderSampleDetail(id) {
    var sample = getSampleById(id);
    if (!sample) { switchMenu('sample-list'); return; }
    currentSampleId = id;

    document.getElementById('slDetailPageTitle').textContent = '样本详情 - ' + id;
    document.getElementById('slDetailId').value = id;
    document.getElementById('slDetailType').value = sample.contentType || 'text';
    document.getElementById('slDetailStatus').value = sample.status || 'pass';
    document.getElementById('slDetailSource').value = sample.source || 'manual';
    document.getElementById('slDetailReason').value = sample.reviewReason || '';
    document.getElementById('btnSlDelete').style.display = 'inline-block';

    // Content type toggle
    var isText = sample.contentType === 'text';
    document.getElementById('slDetailTextFields').style.display = isText ? '' : 'none';
    document.getElementById('slDetailImageFields').style.display = isText ? 'none' : '';
    document.getElementById('slDetailTitle').value = sample.title || '';
    document.getElementById('slDetailText').value = isText ? (sample.content || '') : '';
    document.getElementById('slDetailImgTitle').value = sample.title || '';
    document.getElementById('slDetailImgUrl').value = sample.imageUrl || '';

    // Populate category dropdown
    var catSelect = document.getElementById('slDetailCategory');
    catSelect.innerHTML = '';
    sampleTags.filter(function (t) { return t.level === 1 && t.status === 'enabled'; }).forEach(function (t) {
      catSelect.innerHTML += '<option value="' + t.id + '"' + (sample.categoryId === t.id ? ' selected' : '') + '>' + t.name + '</option>';
    });

    // Tag pills
    renderSlTagPills(sample.tagIds || [], sample.categoryId);

    // Content display (left side)
    var contentHtml = '';
    if (sample.contentType === 'text') {
      contentHtml = '<div class="sl-content-text">' +
        '<h4>标题</h4><p>' + (sample.title || '-') + '</p>' +
        '<h4>文本内容</h4><pre>' + (sample.content || '') + '</pre>' +
        '</div>';
    } else {
      contentHtml = '<div class="sl-content-image">' +
        '<h4>标题</h4><p>' + (sample.title || '-') + '</p>' +
        '<img src="' + (sample.imageUrl || '') + '" style="max-width:100%;max-height:400px;border-radius:6px;" onerror="this.alt=\'图片加载失败\'">' +
        '</div>';
    }
    document.getElementById('slDetailContent').innerHTML = contentHtml;

    // Audit history
    var historyHtml = '<h4 style="margin-bottom:12px;">操作记录</h4>';
    if (sample.auditHistory && sample.auditHistory.length) {
      historyHtml += '<table class="table"><thead><tr><th>时间</th><th>操作</th><th>详情</th><th>操作人</th></tr></thead><tbody>';
      sample.auditHistory.forEach(function (h) {
        historyHtml += '<tr><td>' + formatTime(h.time) + '</td><td>' + h.action + '</td><td>' + h.detail + '</td><td>' + (h.operator || '-') + '</td></tr>';
      });
      historyHtml += '</tbody></table>';
    } else {
      historyHtml += '<p class="text-muted">暂无操作记录</p>';
    }
    document.getElementById('slDetailHistory').innerHTML = historyHtml;
  }

  function renderSlTagPills(tagIds, categoryId) {
    var container = document.getElementById('slDetailTagPills');
    if (!container) return;
    // Show all enabled tags from the selected category, with checkboxes
    var childTags = getSampleChildTags(categoryId);
    if (childTags.length === 0) {
      container.innerHTML = '<span class="form-hint">该分类暂无二级标签</span>';
      return;
    }
    container.innerHTML = childTags.map(function (t) {
      var checked = tagIds.indexOf(t.id) !== -1;
      return '<label class="sl-tag-pill' + (checked ? ' checked' : '') + '">' +
        '<input type="checkbox" value="' + t.id + '"' + (checked ? ' checked' : '') + ' data-sl-tag-checkbox>' +
        '<span>' + t.name + '</span></label>';
    }).join('');

    // Also show grandchild tags for checked parent tags
    tagIds.forEach(function (tid) {
      var grandchildren = getSampleChildTags(tid);
      if (grandchildren.length > 0) {
        var subHtml = '<div class="sl-sub-tags" data-parent="' + tid + '">' +
          grandchildren.map(function (st) {
            var subChecked = tagIds.indexOf(st.id) !== -1;
            return '<label class="sl-tag-pill sub' + (subChecked ? ' checked' : '') + '">' +
              '<input type="checkbox" value="' + st.id + '"' + (subChecked ? ' checked' : '') + ' data-sl-tag-checkbox>' +
              '<span>' + st.name + '</span></label>';
          }).join('') + '</div>';
        container.innerHTML += subHtml;
      }
    });
  }

  // ── Tag Management ───────────────────────────────────────────────
  function renderSampleTagsLegacyUnused() {
    var tree = document.getElementById('slTagTree');
    var lvl1Tags = sampleTags.filter(function (t) { return t.level === 1; }).sort(function (a, b) { return (a.sortOrder || 0) - (b.sortOrder || 0); });

    var searchInput = document.getElementById('slTagSearchInput');
    var searchTerm = (searchInput && searchInput.value || '').toLowerCase();

    function isTagVisible(t) {
      if (!searchTerm) return true;
      return (t.name || '').toLowerCase().indexOf(searchTerm) !== -1 ||
             (t.code || '').toLowerCase().indexOf(searchTerm) !== -1;
    }

    var html = '<ul class="sl-tree">';
    lvl1Tags.forEach(function (t1) {
      var t1MatchesSearch = isTagVisible(t1);
      var expanded = searchTerm ? t1MatchesSearch : slExpandedTagIds[t1.id];
      if (searchTerm) {
        var lvl2s = sampleTags.filter(function(t){return t.parentId === t1.id;});
        var lvl3s = sampleTags.filter(function(t){return lvl2s.some(function(l2){return t.parentId === l2.id;});});
        if (lvl2s.some(isTagVisible) || lvl3s.some(isTagVisible)) expanded = true;
      }
      if (!searchTerm && !t1MatchesSearch) {
        var desc = sampleTags.filter(function(t){return (t.path||'').indexOf(t1.name+'/')===0;});
        if (!desc.some(isTagVisible) && !t1MatchesSearch) return;
      }

      var lvl1SampleCount = sampleLibrary.filter(function (s) { return s.categoryId === t1.id; }).length;
      html += '<li class="sl-tree-item">';
      html += '<div class="sl-tree-row sl-tree-row--parent" data-tag-id="' + t1.id + '">';
      html += '<span class="sl-tree-toggle" data-tag-id="' + t1.id + '">' + (expanded ? '▾' : '▸') + '</span>';
      html += '<span class="sl-tree-name">' + escHtml(t1.name) + '</span>';
      if (lvl1SampleCount > 0) html += '<span class="sl-tree-count">' + lvl1SampleCount + ' 条</span>';
      html += '</div>';

      // Level 2 children
      if (expanded) {
        var lvl2Tags = sampleTags.filter(function(t){return t.parentId === t1.id;}).sort(function(a,b){return (a.sortOrder||0)-(b.sortOrder||0);});
        if (lvl2Tags.length > 0) {
          html += '<ul class="sl-tree sl-tree-sub">';
          lvl2Tags.forEach(function (t2) {
            if (searchTerm && !isTagVisible(t2)) {
              var lvl3s = sampleTags.filter(function(t){return t.parentId === t2.id;});
              if (!lvl3s.some(isTagVisible)) return;
            }
            var exp2 = searchTerm ? true : slExpandedTagIds[t2.id];
            html += '<li class="sl-tree-item">';
            html += '<div class="sl-tree-row sl-tree-row--parent" data-tag-id="' + t2.id + '">';
            html += '<span class="sl-tree-toggle" data-tag-id="' + t2.id + '">' + (exp2 ? '▾' : '▸') + '</span>';
            html += '<span class="sl-tree-name">' + escHtml(t2.name) + '</span>';
            html += '</div>';

            // Level 3 children
            if (exp2) {
              var lvl3Tags = sampleTags.filter(function(t){return t.parentId === t2.id;}).sort(function(a,b){return (a.sortOrder||0)-(b.sortOrder||0);});
              if (lvl3Tags.length > 0) {
                html += '<ul class="sl-tree sl-tree-sub">';
                lvl3Tags.forEach(function (t3) {
                  if (searchTerm && !isTagVisible(t3)) return;
                  var caseCount = labelCases.filter(function(c){return c.labelId===t3.id;}).length;
                  html += '<li class="sl-tree-item">';
                  html += '<div class="sl-tree-row sl-tree-row--level3" data-tag-id="' + t3.id + '">';
                  html += '<span class="sl-tree-leaf"></span>';
                  html += '<span class="sl-tree-name">' + escHtml(t3.name) + '</span>';
                  if (caseCount > 0) html += '<span class="sl-tree-count">' + caseCount + ' 案例</span>';
                  html += '</div></li>';
                });
                html += '</ul>';
              }
            }
            html += '</li>';
          });
          html += '</ul>';
        }
      }
      html += '</li>';
    });
    html += '</ul>';
    tree.innerHTML = html;

    // Highlight active tag row
    if (currentRuleTagId) {
      var activeRow = tree.querySelector('.sl-tree-row[data-tag-id="' + currentRuleTagId + '"]');
      if (activeRow) activeRow.classList.add('sl-tree-row--active');
    }

    // Click handler for tree nodes (view detail)
    tree.querySelectorAll('.sl-tree-row').forEach(function (row) {
      row.addEventListener('click', function (e) {
        if (e.target.closest('button') || e.target.closest('.sl-tree-toggle')) return;
        showTagDetail(row.dataset.tagId);
      });
    });
  }

  function showTagDetailLegacyUnused(tagId) {
    var tag = getSampleTagById(tagId);
    if (!tag) return;
    if (tag.level < 3) {
      // For level-1 and level-2, just toggle expand (handled by tree click)
      return;
    }
    currentRuleTagId = tagId;
    currentRuleTab = 'basic';
    renderTagRulePanel(tagId);
  }

  function renderSampleTags() {
    var tree = document.getElementById('slTagTree');
    if (!tree) return;
    var searchInput = document.getElementById('slTagSearchInput');
    var searchTerm = (searchInput && searchInput.value || '').toLowerCase();
    var lvl1Tags = sampleTags
      .filter(function (tag) { return tag.level === 1; })
      .sort(function (a, b) { return (a.sortOrder || 0) - (b.sortOrder || 0); });

    function isTagVisible(tag) {
      if (!searchTerm) return true;
      return (tag.name || '').toLowerCase().indexOf(searchTerm) !== -1 ||
        (tag.code || '').toLowerCase().indexOf(searchTerm) !== -1;
    }

    function hasVisibleDescendant(tagId) {
      return sampleTags.some(function (tag) {
        return tag.parentId === tagId && (isTagVisible(tag) || hasVisibleDescendant(tag.id));
      });
    }

    function renderTagRow(tag) {
      // Only expand level-1 → level-2; hide level-3 in left tree
      var children = tag.level < 2 ? getSampleChildTags(tag.id) : [];
      var hasChildren = children.length > 0;
      var expanded = searchTerm ? true : !!slExpandedTagIds[tag.id];
      var tagCount = getSampleThirdLevelTagCount(tag.id);
      var cls = 'sl-tree-row sl-tree-row--level' + tag.level + (hasChildren ? ' sl-tree-row--parent' : ' sl-tree-row--leaf');
      var html = '<li class="sl-tree-item">';
      html += '<div class="' + cls + '" data-tag-id="' + tag.id + '">';
      if (hasChildren) {
        html += '<button type="button" class="sl-tree-toggle" data-tag-id="' + tag.id + '" title="展开/收起">' + (expanded ? '▾' : '▸') + '</button>';
      } else {
        html += '<span class="sl-tree-leaf"></span>';
      }
      html += '<span class="sl-tree-name">' + escHtml(tag.name) + '</span>';
      if (tag.level < 3) html += '<span class="sl-tree-count" title="level-3 tag count">' + tagCount + '</span>';
      html += '<span class="sl-tree-actions">';
      html += '<button type="button" class="sl-tree-menu-btn" data-sl-tag-menu="' + tag.id + '" title="tag actions">...</button>';
      html += '</span></div>';

      if (hasChildren && expanded) {
        html += '<ul class="sl-tree sl-tree-sub">';
        children.forEach(function (child) {
          if (searchTerm && !isTagVisible(child) && !hasVisibleDescendant(child.id)) return;
          html += renderTagRow(child);
        });
        html += '</ul>';
      }
      html += '</li>';
      return html;
    }

    var html = '<ul class="sl-tree">';
    lvl1Tags.forEach(function (tag) {
      if (searchTerm && !isTagVisible(tag) && !hasVisibleDescendant(tag.id)) return;
      html += renderTagRow(tag);
    });
    html += '</ul>';
    tree.innerHTML = html;

    if (currentRuleTagId) {
      var activeRow = tree.querySelector('.sl-tree-row[data-tag-id="' + currentRuleTagId + '"]');
      if (activeRow) activeRow.classList.add('sl-tree-row--active');
    }
  }

  function showTagDetail(tagId) {
    var tag = getSampleTagById(tagId);
    if (!tag) return;
    currentRuleTagId = tagId;
    var tree = document.getElementById('slTagTree');
    if (tree) {
      tree.querySelectorAll('.sl-tree-row--active').forEach(function (row) { row.classList.remove('sl-tree-row--active'); });
      var activeRow = tree.querySelector('.sl-tree-row[data-tag-id="' + tagId + '"]');
      if (activeRow) activeRow.classList.add('sl-tree-row--active');
    }
    if (tag.level === 1) {
      slExpandedTagIds[tagId] = !slExpandedTagIds[tagId];
      renderSampleTags();
      if (tree) {
        var activeRow2 = tree.querySelector('.sl-tree-row[data-tag-id="' + tagId + '"]');
        if (activeRow2) activeRow2.classList.add('sl-tree-row--active');
      }
      renderTagSummaryPanel(tagId);
      return;
    }
    if (tag.level === 2) {
      slExpandedL3CardId = null;
      renderL2ChildrenAccordion(tagId);
      return;
    }
    currentRuleTab = 'basic';
    renderTagRulePanel(tagId);
  }

  function renderTagSummaryPanel(tagId) {
    var tag = getSampleTagById(tagId);
    var panel = document.getElementById('slTagEditPanel');
    if (!tag || !panel) return;
    var children = getSampleChildTags(tag.id);
    var sampleCount = getSampleTagSampleCount(tag.id);
    var caseCount = getSampleTagCaseCount(tag.id);
    var html = '<div class="sl-rule-toolbar">';
    html += '<div class="sl-rule-breadcrumb">' + renderRuleBreadcrumb(tag) + '</div>';
    html += '<div class="sl-rule-toolbar-actions">';
    html += '<button class="btn btn-secondary btn-sm" data-sl-panel-actions="' + tag.id + '">&#26631;&#31614;&#25805;&#20316;</button>';
    html += '</div></div>';
    html += '<div class="sl-tag-summary-grid">';
    html += '<div class="sl-tag-summary-card"><b>' + sampleCount + '</b><span>关联样本</span></div>';
    html += '<div class="sl-tag-summary-card"><b>' + children.length + '</b><span>直接子标签</span></div>';
    html += '<div class="sl-tag-summary-card"><b>' + caseCount + '</b><span>案例数</span></div>';
    html += '</div>';
    html += '<div class="sl-tag-info">';
    html += '<p><b>标签层级</b> ' + tag.level + ' 级</p>';
    html += '<p><b>标签路径</b> ' + escHtml(tag.path || tag.name) + '</p>';
    html += '<p><b>&#26631;&#31614;&#20540;</b> ' + escHtml(tag.code || tag.id || '-') + '</p>';
    html += '<p><b>标签说明</b> ' + escHtml(tag.description || '暂无说明') + '</p>';
    html += '</div>';
    panel.innerHTML = html;
  }

  function renderTagRulePanel(tagId) {
    var tag = getSampleTagById(tagId);
    var panel = document.getElementById('slTagEditPanel');
    if (!panel) return;
    if (!tag || tag.level < 3) {
      panel.innerHTML = '<h3 class="sl-tag-edit-title">&#36873;&#25321;&#19977;&#32423;&#26631;&#31614;</h3><p class="form-hint">&#28857;&#20987;&#24038;&#20391;&#20108;&#32423;&#26631;&#31614;&#26597;&#30475;&#21644;&#32534;&#36753;&#19977;&#32423;&#35268;&#21017;</p>';
      return;
    }
    currentRuleTagId = tagId;

    var html = '<div class="sl-rule-toolbar">';
    html += '<div class="sl-rule-breadcrumb">' + renderRuleBreadcrumb(tag) + '</div>';
    html += '<div class="sl-rule-toolbar-actions">';
    html += '<button class="btn btn-success btn-sm" id="btnRulePublish">&#20445;&#23384;&#24182;&#21457;&#24067;</button>';
    html += '</div></div>';
    html += renderUnifiedRuleEditor(tag);
    panel.innerHTML = html;
  }

  // ── Level-2 Children Accordion (expandable L3 cards) ─────────
  function renderL2ChildrenAccordion(tagId) {
    var tag = getSampleTagById(tagId);
    var panel = document.getElementById('slTagEditPanel');
    if (!tag || !panel) return;
    currentRuleTagId = tagId;

    var l3Children = getSampleChildTags(tag.id);
    var html = '<div class="sl-rule-toolbar">';
    html += '<div class="sl-rule-breadcrumb">' + renderRuleBreadcrumb(tag) + '</div>';
    html += '<div class="sl-rule-toolbar-actions">';
    html += '<button class="btn btn-secondary btn-sm" data-sl-panel-actions="' + tag.id + '">标签操作</button>';
    html += '</div></div>';

    if (l3Children.length === 0) {
      html += '<div class="sl-l3-empty"><p>该二级标签下暂无三级标签，请先添加三级子标签。</p></div>';
    } else {
      html += '<div class="sl-l3-accordion">';
      l3Children.forEach(function(child) {
        var isExpanded = slExpandedL3CardId === child.id;
        html += '<div class="sl-l3-card' + (isExpanded ? ' sl-l3-card--expanded' : '') + '" data-l3-card="' + child.id + '">';
        html += '<div class="sl-l3-card-header" data-l3-toggle="' + child.id + '">';
        html += '<span class="sl-l3-card-arrow">' + (isExpanded ? '▾' : '▸') + '</span>';
        html += '<span class="sl-l3-card-name">' + escHtml(child.name) + '</span>';
        html += '<span class="sl-l3-card-code">' + escHtml(child.code || '') + '</span>';
        html += '</div>';
        if (isExpanded) {
          currentRuleTagId = child.id;
          html += '<div class="sl-l3-card-body">';
          html += renderUnifiedRuleEditor(child);
          html += '<div class="form-actions" style="padding:12px 0 0 0;">';
          html += '<button class="btn btn-success btn-sm" id="btnRulePublish">保存并发布</button>';
          html += '</div>';
          html += '</div>';
        }
        html += '</div>';
      });
      html += '</div>';
    }
    panel.innerHTML = html;
  }

  function renderRuleBreadcrumb(tag) {
    var parts = (tag.path || tag.name).split('/');
    return parts.map(function(p, i) {
      return '<span class="sl-breadcrumb-seg' + (i === parts.length - 1 ? ' sl-breadcrumb-seg--last' : '') + '">' + escHtml(p) + '</span>';
    }).join('<span class="sl-breadcrumb-arrow">&gt;</span>');
  }

  function switchRuleTab(tabName) {
    currentRuleTab = tabName;
    if (currentRuleTagId) renderTagRulePanel(currentRuleTagId);
  }

  // ════════════════════════════════════════════════════════════════
  // Tab 1: Basic Info
  // ════════════════════════════════════════════════════════════════
  function renderBasicInfoTab(tag) {
    var parent = tag.parentId ? getSampleTagById(tag.parentId) : null;
    var grandParent = parent && parent.parentId ? getSampleTagById(parent.parentId) : null;
    var lvl1Tags = sampleTags.filter(function(t){return t.level===1;});
    var lvl2Options = [];
    if (grandParent) {
      lvl2Options = sampleTags.filter(function(t){return t.level===2 && t.parentId===grandParent.id;});
    }

    var html = '<div class="sl-basic-form">';
    // Row 1: Name + Value + Description (matches modal order)
    html += '<div class="form-row form-row-tag"><div class="form-group">';
    html += '<label class="form-label">标签名称 <span class="required">*</span></label>';
    html += '<input type="text" id="slBasicName" class="form-input" value="' + escHtml(tag.name) + '" maxlength="50">';
    html += '</div><div class="form-group">';
    html += '<label class="form-label">标签值 <span class="required">*</span></label>';
    html += '<input type="text" id="slBasicCode" class="form-input" value="' + escHtml(tag.code || '') + '" maxlength="80">';
    html += '</div><div class="form-group">';
    html += '<label class="form-label">标签说明 <span class="required">*</span></label>';
    html += '<input type="text" id="slBasicDesc" class="form-input" value="' + escHtml(tag.description || '') + '" maxlength="200" placeholder="请输入标签说明">';
    html += '</div></div>';
    // Category (level-1 + level-2)
    html += '<div class="form-row"><div class="form-group">';
    html += '<label class="form-label">所属一级分类 <span class="required">*</span></label>';
    html += '<select id="slBasicCat1" class="form-select">';
    lvl1Tags.forEach(function(t){ html += '<option value="'+t.id+'"'+(grandParent&&grandParent.id===t.id?' selected':'')+'>'+t.name+'</option>'; });
    html += '</select></div><div class="form-group">';
    html += '<label class="form-label">所属二级标签 <span class="required">*</span></label>';
    html += '<select id="slBasicCat2" class="form-select">';
    html += '<option value="">请先选择一级分类</option>';
    (grandParent ? sampleTags.filter(function(t){return t.level===2&&t.parentId===grandParent.id;}) : []).forEach(function(t){
      html += '<option value="'+t.id+'"'+(parent&&parent.id===t.id?' selected':'')+'>'+t.name+'</option>';
    });
    html += '</select></div></div>';

    // Content type
    html += '<div class="form-group"><label class="form-label">适用内容类型 <span class="required">*</span></label>';
    html += '<div class="checkbox-group">';
    html += '<label class="checkbox-label"><input type="checkbox" id="slBasicCtText" value="text"' + (tag.applicableContentTypes.indexOf('text')!==-1?' checked':'') + '> 文本</label>';
    html += '<label class="checkbox-label"><input type="checkbox" id="slBasicCtImage" value="image"' + (tag.applicableContentTypes.indexOf('image')!==-1?' checked':'') + '> 图片</label>';
    html += '</div></div>';

    // Suggested status + risk level
    html += '<div class="form-row"><div class="form-group">';
    html += '<label class="form-label">建议审核状态 <span class="required">*</span></label>';
    html += '<div class="checkbox-group">';
    ['reject','suspect','pass'].forEach(function(v){
      var labels = {reject:'不通过',suspect:'嫌疑',pass:'通过'};
      html += '<label class="checkbox-label"><input type="radio" name="slBasicSuggStatus" value="'+v+'"'+(tag.suggestedStatus===v?' checked':'')+'> '+labels[v]+'</label>';
    });
    html += '</div></div><div class="form-group">';
    html += '<label class="form-label">风险等级 <span class="required">*</span></label>';
    html += '<div class="checkbox-group">';
    ['high','medium','low'].forEach(function(v){
      var labels = {high:'高',medium:'中',low:'低'};
      html += '<label class="checkbox-label"><input type="radio" name="slBasicRiskLevel" value="'+v+'"'+(tag.riskLevel===v?' checked':'')+'> '+labels[v]+'</label>';
    });
    html += '</div></div></div>';

    // Status display + owner
    html += '<div class="form-row"><div class="form-group">';
    html += '<label class="form-label">状态</label>';
    var statusLabels = {draft:'草稿',active:'生效中',disabled:'已停用'};
    html += '<p style="padding-top:8px;"><span class="badge '+(tag.status==='active'?'badge-pass':tag.status==='disabled'?'badge-secondary':'badge-suspect')+'">'+(statusLabels[tag.status]||tag.status)+'</span></p>';
    html += '</div><div class="form-group">';
    html += '<label class="form-label" for="slBasicOwner">负责人</label>';
    html += '<input type="text" id="slBasicOwner" class="form-input" value="' + escHtml(tag.ownerId || '') + '" placeholder="选填">';
    html += '</div></div>';

    html += '</div>';
    return html;
  }

  // ════════════════════════════════════════════════════════════════
  // Tab 2: Rule Settings
  // ════════════════════════════════════════════════════════════════
  function renderRuleSettingsTab(tag) {
    var contentTypes = tag.applicableContentTypes || ['text'];
    var html = '';
    // Sub-tabs for text/image
    if (contentTypes.length > 1) {
      html += '<div class="ct-tabs" style="margin-bottom:14px;">';
      contentTypes.forEach(function(ct){
        html += '<button class="ct-tab'+(currentRuleContentType===ct?' active':'')+'" data-rule-ct="'+ct+'">'+(ct==='text'?'文本规则':'图片规则')+'</button>';
      });
      html += '</div>';
    }
    var ct = (contentTypes.length === 1) ? contentTypes[0] : currentRuleContentType;
    var rule = getLabelRule(tag.id, ct) || { ruleSummary:'', keywords:[], semanticFeatures:'', visualFeatures:'', ocrFeatures:[], hitConditions:[], excludeConditions:[], disposalSuggestion:'reject', applicableScenes:[] };

    html += '<div class="sl-rule-form">';
    html += '<div class="form-group"><label class="form-label">规则摘要 <span class="required">*</span></label>';
    html += '<textarea id="slRuleSummary" class="form-textarea" rows="3" style="min-height:64px;">' + escHtml(rule.ruleSummary || '') + '</textarea></div>';

    if (ct === 'text') {
      html += '<div class="form-group"><label class="form-label">关键词</label>';
      html += '<div class="sl-tag-input-wrap"><div class="sl-tag-input-tags" id="slRuleKeywords">';
      (rule.keywords || []).forEach(function(kw){ html += '<span class="sl-tag-chip">' + escHtml(kw) + '<span class="sl-tag-chip-x">×</span></span>'; });
      html += '</div>';
      html += '<input type="text" class="form-input" id="slRuleKeywordInput" placeholder="输入关键词，回车添加" style="font-size:12px;"></div></div>';
      html += '<div class="form-group"><label class="form-label">语义特征 <span class="required">*</span></label>';
      html += '<textarea id="slRuleSemantic" class="form-textarea" rows="2" style="min-height:52px;">' + escHtml(rule.semanticFeatures || '') + '</textarea></div>';
    } else {
      html += '<div class="form-group"><label class="form-label">视觉特征 <span class="required">*</span></label>';
      html += '<textarea id="slRuleVisual" class="form-textarea" rows="2" style="min-height:52px;">' + escHtml(rule.visualFeatures || '') + '</textarea></div>';
      html += '<div class="form-group"><label class="form-label">OCR 特征</label>';
      html += '<div class="sl-tag-input-wrap"><div class="sl-tag-input-tags" id="slRuleOcrFeatures">';
      (rule.ocrFeatures || []).forEach(function(f){ html += '<span class="sl-tag-chip">' + escHtml(f) + '<span class="sl-tag-chip-x">×</span></span>'; });
      html += '</div>';
      html += '<input type="text" class="form-input" id="slRuleOcrInput" placeholder="输入OCR关键词，回车添加" style="font-size:12px;"></div></div>';
    }

    // Hit conditions
    html += '<div class="sl-rule-section"><div class="sl-rule-section-title">命中条件 <span class="sl-rule-count">'+(rule.hitConditions||[]).length+'</span></div>';
    html += '<div class="sl-condition-list" id="slHitCondList">';
    (rule.hitConditions||[]).forEach(function(c,i){ html += renderConditionRow('hit', tag.id, c, i, ct); });
    html += '</div>';
    html += '<button class="sl-add-btn" id="btnAddHitCond">+ 添加命中条件</button></div>';

    // Exclude conditions
    html += '<div class="sl-rule-section"><div class="sl-rule-section-title">排除条件 <span class="sl-rule-count">'+(rule.excludeConditions||[]).length+'</span></div>';
    html += '<div class="sl-condition-list" id="slExcCondList">';
    (rule.excludeConditions||[]).forEach(function(c,i){ html += renderConditionRow('exc', tag.id, c, i, ct); });
    html += '</div>';
    html += '<button class="sl-add-btn" id="btnAddExcCond">+ 添加排除条件</button></div>';

    // Disposal suggestion + scenes
    html += '<div class="form-row"><div class="form-group">';
    html += '<label class="form-label">处置建议 <span class="required">*</span></label>';
    html += '<select id="slRuleDisposal" class="form-select">';
    [{v:'reject',l:'不通过'},{v:'pass',l:'通过'},{v:'manual_review',l:'人工复核'}].forEach(function(o){
      html += '<option value="'+o.v+'"'+(rule.disposalSuggestion===o.v?' selected':'')+'>'+o.l+'</option>';
    });
    html += '</select></div><div class="form-group">';
    html += '<label class="form-label" for="slRuleScenes">适用场景</label>';
    html += '<input type="text" id="slRuleScenes" class="form-input" value="' + escHtml((rule.applicableScenes||[]).join(',')) + '" placeholder="评论,私信,动态（逗号分隔）">';
    html += '</div></div>';

    html += '<input type="hidden" id="slRuleContentType" value="'+ct+'">';
    html += '</div>';
    return html;
  }

  function renderConditionRow(type, tagId, c, idx, contentType) {
    var ct = contentType || currentRuleContentType || 'text';
    var fields = { content: '内容', title: '标题' };
    var ops = { contains: '包含', regex: '正则', equals: '等于' };
    var html = '<div class="sl-condition-row">';
    html += '<select class="form-select sl-cond-field" data-idx="'+idx+'" data-prop="field">';
    Object.keys(fields).forEach(function(k){ html += '<option value="'+k+'"'+(c.field===k?' selected':'')+'>'+fields[k]+'</option>'; });
    html += '</select>';
    html += '<select class="form-select sl-cond-op" data-idx="'+idx+'" data-prop="operator">';
    Object.keys(ops).forEach(function(k){ html += '<option value="'+k+'"'+(c.operator===k?' selected':'')+'>'+ops[k]+'</option>'; });
    html += '</select>';
    html += '<input type="text" class="form-input sl-cond-value" data-idx="'+idx+'" data-prop="value" value="'+escHtml(c.value||'')+'" placeholder="匹配值">';
    html += '<button class="sl-cond-remove" data-action="remove-'+type+'-cond" data-idx="'+idx+'">×</button>';
    html += '</div>';
    return html;
  }

  // ════════════════════════════════════════════════════════════════
  // Tab 3/4: Cases (positive/negative)
  // ════════════════════════════════════════════════════════════════
  function renderCasesTab(tag, caseType) {
    var cases = getLabelCases(tag.id, caseType);
    var titleLabel = caseType === 'positive' ? '正例' : '反例';
    var html = '<div class="sl-case-tab">';
    html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">';
    html += '<span style="font-size:13px;color:var(--text-muted);">共 ' + cases.length + ' 条' + titleLabel + '</span>';
    html += '<button class="btn btn-primary btn-sm" id="btnAddCase" data-case-type="'+caseType+'">新增' + titleLabel + '</button>';
    html += '</div>';

    if (cases.length === 0) {
      html += '<div class="sl-case-empty">暂无' + titleLabel + '案例，点击"新增' + titleLabel + '"添加</div>';
    } else {
      html += '<div class="sl-case-list">';
      cases.forEach(function(c) {
        var reviewBadge = {pending:'badge-suspect',confirmed:'badge-pass',discarded:'badge-secondary'};
        var reviewLabel = {pending:'待审核',confirmed:'已确认',discarded:'已废弃'};
        html += '<div class="sl-case-item" data-case-id="'+c.id+'">';
        html += '<div class="sl-case-item-head">';
        html += '<span class="badge '+(c.contentType==='text'?'badge-info':'badge-pass')+'">'+(c.contentType==='text'?'文本':'图片')+'</span>';
        html += '<span class="badge '+reviewBadge[c.reviewStatus]+'">'+reviewLabel[c.reviewStatus]+'</span>';
        html += '<span style="font-size:12px;color:var(--text-muted);">判定: '+(c.judgmentStatus==='reject'?'不通过':c.judgmentStatus==='pass'?'通过':'嫌疑')+'</span>';
        html += '<span style="flex:1;"></span>';
        html += '<button class="btn-link btn-sm" data-action="edit-case" data-id="'+c.id+'">编辑</button>';
        html += '<button class="btn-link btn-sm" data-action="delete-case" data-id="'+c.id+'" style="color:var(--danger);">删除</button>';
        html += '</div>';
        html += '<div class="sl-case-item-body">' + escHtml((c.textContent || c.imageUrl || '').substring(0, 120)) + '</div>';
        if (c.judgmentReason) html += '<div class="sl-case-item-reason">理由: ' + escHtml(c.judgmentReason.substring(0, 80)) + '</div>';
        html += '</div>';
      });
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  // ════════════════════════════════════════════════════════════════
  // Tab 5: Related Samples
  // ════════════════════════════════════════════════════════════════
  function renderRelatedSamplesTab(tag) {
    var samples = sampleLibrary.filter(function(s){return s.tagIds && s.tagIds.indexOf(tag.id)!==-1;});
    var html = '<div class="sl-samples-tab">';
    html += '<span style="font-size:13px;color:var(--text-muted);">共 ' + samples.length + ' 条关联样本</span>';
    if (samples.length === 0) {
      html += '<p class="form-hint" style="padding:20px 0;">暂无样本关联此标签</p>';
    } else {
      html += '<div class="table-wrap" style="margin-top:12px;"><table class="table"><thead><tr>';
      html += '<th>样本ID</th><th>内容预览</th><th>类型</th><th>审核状态</th><th>来源</th><th>更新时间</th><th>操作</th></tr></thead><tbody>';
      samples.forEach(function(s){
        var tagName = getSampleTagById(s.categoryId);
        html += '<tr>';
        html += '<td><code>'+s.id+'</code></td>';
        html += '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">'+escHtml((s.content||s.title||'').substring(0,40))+'</td>';
        html += '<td>'+contentTypeLabel(s.contentType)+'</td>';
        html += '<td>'+slStatusBadge(s.status)+'</td>';
        html += '<td>'+slSourceLabel(s.source)+'</td>';
        html += '<td>'+formatTime(s.updatedAt)+'</td>';
        html += '<td>';
        html += '<a class="link" data-action="sl-view" data-id="'+s.id+'" href="#">查看</a> ';
        html += '<a class="link" data-action="sl-sample-to-case" data-sample-id="'+s.id+'" data-tag-id="'+tag.id+'" href="#">设为案例</a>';
        html += '</td></tr>';
      });
      html += '</tbody></table></div>';
    }
    html += '</div>';
    return html;
  }

  // ════════════════════════════════════════════════════════════════
  // Tab 6: Version History
  // ════════════════════════════════════════════════════════════════
  function renderVersionsTab(tag) {
    var versions = labelVersions.filter(function(v){return v.labelId===tag.id;}).sort(function(a,b){return (b.version||'').localeCompare(a.version||'');});
    var html = '<div class="sl-versions-tab">';
    html += '<span style="font-size:13px;color:var(--text-muted);">共 ' + versions.length + ' 条版本记录</span>';
    if (versions.length === 0) {
      html += '<p class="form-hint" style="padding:20px 0;">暂无版本记录，发布规则后将自动生成版本</p>';
    } else {
      html += '<div class="table-wrap" style="margin-top:12px;"><table class="table"><thead><tr>';
      html += '<th>版本号</th><th>变更类型</th><th>变更内容</th><th>影响范围</th><th>操作时间</th><th>生效状态</th></tr></thead><tbody>';
      versions.forEach(function(v){
        var changeLabels = {initial:'初始版本',basic_info:'基础信息',text_rule:'文本规则',image_rule:'图片规则',cases:'案例',status:'状态变更'};
        var statusBadge = v.status==='active'?'badge-pass':'badge-secondary';
        html += '<tr>';
        html += '<td><strong>v'+v.version+'</strong></td>';
        html += '<td>'+(changeLabels[v.changeType]||v.changeType)+'</td>';
        html += '<td>'+escHtml((v.changeSummary||'').substring(0,40))+'</td>';
        html += '<td>'+escHtml((v.impactScope||[]).join('、')||'-')+'</td>';
        html += '<td>'+formatTime(v.createdAt)+'</td>';
        html += '<td><span class="badge '+statusBadge+'">'+(v.status==='active'?'生效中':'已归档')+'</span></td>';
        html += '</tr>';
      });
      html += '</tbody></table></div>';
    }
    html += '</div>';
    return html;
  }

  // ════════════════════════════════════════════════════════════════
  // Rule Actions
  // ════════════════════════════════════════════════════════════════

  function renderUnifiedRuleEditor(tag) {
    var html = '<div class="sl-unified-rule-editor">';
    html += '<section class="sl-unified-section">';
    html += '<h4 class="sl-unified-title">&#22522;&#30784;&#20449;&#24687;</h4>';
    html += '<div class="form-row form-row-tag"><div class="form-group">';
    html += '<label class="form-label" for="slBasicName">&#26631;&#31614;&#21517;&#31216; <span class="required">*</span></label>';
    html += '<input type="text" id="slBasicName" class="form-input" value="' + escHtml(tag.name || '') + '" maxlength="50">';
    html += '</div><div class="form-group">';
    html += '<label class="form-label" for="slBasicCode">&#26631;&#31614;&#20540; <span class="required">*</span></label>';
    html += '<input type="text" id="slBasicCode" class="form-input" value="' + escHtml(tag.code || '') + '" maxlength="80">';
    html += '</div><div class="form-group">';
    html += '<label class="form-label" for="slBasicDesc">&#26631;&#31614;&#35828;&#26126; <span class="required">*</span></label>';
    html += '<input type="text" id="slBasicDesc" class="form-input" value="' + escHtml(tag.description || '') + '" maxlength="200" placeholder="请输入标签说明">';
    html += '</div></div>';
    html += '</section>';
    html += renderSimpleRuleBlock(tag, 'text');
    html += renderSimpleRuleBlock(tag, 'image');
    html += renderSimpleCaseSection(tag, 'positive');
    html += renderSimpleCaseSection(tag, 'negative');
    html += '</div>';
    return html;
  }

  function renderSimpleRuleBlock(tag, contentType) {
    var rule = getLabelRule(tag.id, contentType) || { contentType: contentType, hitConditions: [], excludeConditions: [], disposalSuggestion: 'reject', applicableScenes: [] };
    var title = contentType === 'text' ? '&#25991;&#26412;&#35268;&#21017;&#35774;&#32622;' : '&#22270;&#29255;&#35268;&#21017;&#35774;&#32622;';
    var html = '<section class="sl-unified-section" data-rule-block="' + contentType + '">';
    html += '<h4 class="sl-unified-title">' + title + '</h4>';
    html += '<div class="sl-rule-section"><div class="sl-rule-section-title">&#21629;&#20013;&#26465;&#20214; <span class="sl-rule-count">' + (rule.hitConditions || []).length + '</span></div>';
    html += '<div class="sl-condition-list" data-simple-cond-list="' + contentType + '|hit">';
    (rule.hitConditions || []).forEach(function (condition) { html += renderSimpleConditionRow(contentType, 'hit', condition); });
    html += '</div><button class="sl-add-btn" data-simple-add-cond="' + contentType + '|hit">+ &#21019;&#24314;&#21629;&#20013;&#35268;&#21017;</button></div>';
    html += '<div class="sl-rule-section"><div class="sl-rule-section-title">&#25490;&#38500;&#26465;&#20214; <span class="sl-rule-count">' + (rule.excludeConditions || []).length + '</span></div>';
    html += '<div class="sl-condition-list" data-simple-cond-list="' + contentType + '|exclude">';
    (rule.excludeConditions || []).forEach(function (condition) { html += renderSimpleConditionRow(contentType, 'exclude', condition); });
    html += '</div><button class="sl-add-btn" data-simple-add-cond="' + contentType + '|exclude">+ &#21019;&#24314;&#25490;&#38500;&#35268;&#21017;</button></div>';
    html += '<div class="form-group"><label class="form-label">&#20351;&#29992;&#22330;&#26223;</label>';
    html += '<input type="text" class="form-input" data-simple-scenes="' + contentType + '" value="' + escHtml((rule.applicableScenes || []).join(',')) + '" placeholder="&#35780;&#35770;,&#31169;&#20449;,&#21160;&#24577;">';
    html += '</div></section>';
    return html;
  }

  function renderSimpleConditionRow(contentType, type, condition) {
    var value = condition && (condition.value || condition.ruleText || condition.text || condition.keyword) || '';
    var label = type === 'hit' ? '&#21629;&#20013;&#35268;&#21017;' : '&#25490;&#38500;&#35268;&#21017;';
    var disposal = condition && condition.disposalSuggestion ? condition.disposalSuggestion : (type === 'hit' ? 'reject' : 'pass');
    var html = '<div class="sl-condition-row sl-simple-condition-row" data-content-type="' + contentType + '" data-cond-type="' + type + '">';
    html += '<input type="text" class="form-input sl-simple-cond-value" value="' + escHtml(value) + '" placeholder="' + label + '">';
    html += '<select class="form-select sl-simple-cond-disposal" title="处置建议">';
    [{v:'reject',l:'不通过'},{v:'suspect',l:'嫌疑'},{v:'pass',l:'通过'}].forEach(function (option) {
      html += '<option value="' + option.v + '"' + (disposal === option.v ? ' selected' : '') + '>' + option.l + '</option>';
    });
    html += '</select>';
    html += '<button class="sl-cond-remove" data-action="remove-simple-cond">&times;</button>';
    html += '</div>';
    return html;
  }

  function renderSimpleCaseSection(tag, caseType) {
    var cases = getLabelCases(tag.id, caseType);
    var title = caseType === 'positive' ? '&#27491;&#26696;&#20363;' : '&#21453;&#26696;&#20363;';
    var html = '<section class="sl-unified-section"><div class="sl-unified-section-head">';
    html += '<h4 class="sl-unified-title">' + title + '</h4>';
    html += '<button class="btn btn-primary btn-sm" id="btnAddCase" data-case-type="' + caseType + '">&#26032;&#22686;' + title + '</button>';
    html += '</div>';
    if (cases.length === 0) {
      html += '<p class="form-hint">&#26242;&#26080;' + title + '</p>';
    } else {
      html += '<div class="sl-case-list">';
      cases.forEach(function (item) {
        html += '<div class="sl-case-item" data-case-id="' + item.id + '">';
        html += '<div class="sl-case-item-head"><span class="badge ' + (item.contentType === 'text' ? 'badge-info' : 'badge-pass') + '">' + (item.contentType === 'text' ? '&#25991;&#26412;' : '&#22270;&#29255;') + '</span><span style="flex:1;"></span>';
        html += '<button class="btn-link btn-sm" data-action="edit-case" data-id="' + item.id + '">&#32534;&#36753;</button>';
        html += '<button class="btn-link btn-sm" data-action="delete-case" data-id="' + item.id + '" style="color:var(--danger);">&#21024;&#38500;</button></div>';
        if (item.contentType === 'image' && item.imageUrl) {
          html += '<div class="sl-case-item-body"><img class="sl-case-thumb" src="' + escHtml(item.imageUrl) + '" alt="案例图片"></div>';
        } else {
          html += '<div class="sl-case-item-body">' + escHtml((item.textContent || '').substring(0, 160)) + '</div>';
        }
        if (item.judgmentReason) html += '<div class="sl-case-item-reason">&#29702;&#30001;: ' + escHtml(item.judgmentReason.substring(0, 100)) + '</div>';
        html += '</div>';
      });
      html += '</div>';
    }
    html += '</section>';
    return html;
  }

  function saveRuleDraft() {
    if (!currentRuleTagId) return;
    var tag = getSampleTagById(currentRuleTagId);
    if (!tag) return;
    collectBasicInfo(tag);
    collectRuleSettings(tag);
    saveSampleTags();
    saveLabelRules();
    saveLabelCases();
    showToast('草稿已保存');
  }

  function publishRule() {
    if (!currentRuleTagId) return;
    var tag = getSampleTagById(currentRuleTagId);
    if (!tag) return;

    // Validate basic info
    var codeEl = document.getElementById('slBasicCode');
    var descEl = document.getElementById('slBasicDesc');
    var nameEl = document.getElementById('slBasicName');
    if (!nameEl || !nameEl.value.trim()) { alert('请填写标签名称'); return; }
    if (!codeEl || !codeEl.value.trim()) { alert('请填写标签值'); return; }
    var dup = sampleTags.filter(function(t){return t.id!==tag.id && t.code===codeEl.value.trim();});
    if (dup.length > 0) { alert('标签值 "'+codeEl.value.trim()+'" 已存在，请更换'); return; }
    if (!descEl || !descEl.value.trim()) { alert('请填写标签说明'); return; }

    // Validate rules
    var hitConds = [];
    document.querySelectorAll('.sl-simple-condition-row[data-cond-type="hit"]').forEach(function(row){
      var v = row.querySelector('.sl-simple-cond-value');
      if (v && v.value.trim()) hitConds.push(true);
    });
    if (hitConds.length === 0) { alert('请至少填写一条命中条件'); return; }

    // Collect and save
    collectBasicInfo(tag);
    collectRuleSettings(tag);
    tag.status = 'active';
    saveSampleTags();
    saveLabelRules();

    // If we're in accordion view (L3 under L2), return to accordion
    var savedTag = getSampleTagById(currentRuleTagId);
    if (savedTag && savedTag.level === 3) {
      var l2Parent = savedTag.parentId ? getSampleTagById(savedTag.parentId) : null;
      if (l2Parent && l2Parent.level === 2) {
        slExpandedL3CardId = currentRuleTagId;
        renderL2ChildrenAccordion(l2Parent.id);
        renderSampleTags();
        showToast('规则已发布');
        return;
      }
    }
    renderTagRulePanel(currentRuleTagId);
    renderSampleTags();
    showToast('规则已发布');
  }

  function disableRuleLabel() {
    if (!currentRuleTagId) return;
    var tag = getSampleTagById(currentRuleTagId);
    if (!tag) return;
    if (tag.status === 'disabled') { alert('该标签已停用'); return; }
    var reason = prompt('请输入停用原因：');
    if (!reason) return;
    // Check references
    var refCount = sampleLibrary.filter(function(s){return s.tagIds && s.tagIds.indexOf(tag.id)!==-1;}).length;
    if (refCount > 0) {
      if (!confirm('当前标签被 '+refCount+' 条样本引用，确认停用？\n历史样本保留标签，新增标注不可再选择此标签。')) return;
    }
    tag.status = 'disabled';
    saveSampleTags();
    // Archive active version
    labelVersions.filter(function(v){return v.labelId===tag.id&&v.status==='active';}).forEach(function(v){v.status='archived';});
    labelVersions.push({
      id: generateId('VER'), labelId: tag.id, version: '---',
      snapshot: {}, changeSummary: '停用标签: '+reason, changeType: 'status', impactScope: ['标注'],
      status: 'active', createdBy: null, createdAt: now()
    });
    saveLabelVersions();
    renderTagRulePanel(currentRuleTagId);
    renderSampleTags();
    showToast('标签已停用');
  }

  function copyRuleLabel() {
    if (!currentRuleTagId) return;
    var tag = getSampleTagById(currentRuleTagId);
    if (!tag) return;
    var newId = generateId('STAG');
    var newTag = JSON.parse(JSON.stringify(tag));
    newTag.id = newId;
    newTag.name = (tag.name || '') + '（副本）';
    newTag.code = (tag.code || '') + '_COPY';
    newTag.status = 'draft';
    newTag.createdAt = now();
    newTag.updatedAt = now();
    sampleTags.push(newTag);
    saveSampleTags();

    // Copy rules
    var rules = labelRules.filter(function(r){return r.labelId===tag.id;});
    rules.forEach(function(r){
      var r2 = JSON.parse(JSON.stringify(r));
      r2.id = generateId('RULE'); r2.labelId = newId; r2.status = 'draft';
      labelRules.push(r2);
    });
    saveLabelRules();
    currentRuleTagId = newId;
    renderSampleTags();
    renderTagRulePanel(newId);
    showToast('标签已复制，请修改标签编码和名称');
  }

  function showToast(msg) {
    var el = document.getElementById('slRuleToast');
    if (!el) {
      el = document.createElement('div');
      el.id = 'slRuleToast';
      el.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);background:#202123;color:#fff;padding:10px 24px;border-radius:8px;font-size:14px;z-index:9999;transition:opacity 0.3s;pointer-events:none;';
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.style.opacity = '1';
    clearTimeout(el._timeout);
    el._timeout = setTimeout(function(){el.style.opacity='0';}, 2000);
  }

  // ── Collect form data helpers ──
  function collectBasicInfo(tag) {
    var codeEl = document.getElementById('slBasicCode');
    var descEl = document.getElementById('slBasicDesc');
    var nameEl = document.getElementById('slBasicName');
    if (codeEl) tag.code = codeEl.value.trim();
    if (descEl) tag.description = descEl.value.trim();
    if (nameEl) tag.name = nameEl.value.trim();
    updateSampleTagPath(tag.id);
    tag.updatedAt = now();
  }

  function collectRuleSettings(tag) {
    ['text', 'image'].forEach(function (ct) {
      var block = document.querySelector('[data-rule-block="' + ct + '"]');
      if (!block) return;
      var rule = getLabelRule(tag.id, ct);
      var isNew = !rule;
      if (isNew) {
        rule = { id: generateId('RULE'), labelId: tag.id, contentType: ct, ruleSummary:'', keywords:[], semanticFeatures:'', visualFeatures:'', ocrFeatures:[], hitConditions:[], excludeConditions:[], disposalSuggestion:'reject', applicableScenes:[], version:1, status:'draft', createdBy:null, createdAt:now(), updatedAt:now() };
      }

      var disposalEl = block.querySelector('[data-simple-disposal="' + ct + '"]');
      if (disposalEl) rule.disposalSuggestion = disposalEl.value;
      var scenesEl = block.querySelector('[data-simple-scenes="' + ct + '"]');
      if (scenesEl) rule.applicableScenes = scenesEl.value.split(',').map(function(s){ return s.trim(); }).filter(Boolean);

      rule.hitConditions = [];
      block.querySelectorAll('.sl-simple-condition-row[data-cond-type="hit"]').forEach(function (row) {
        var input = row.querySelector('.sl-simple-cond-value');
        var disposal = row.querySelector('.sl-simple-cond-disposal');
        var value = input ? input.value.trim() : '';
        if (value) rule.hitConditions.push({ id: generateId('HC'), field: 'rule', operator: 'custom', value: value, disposalSuggestion: disposal ? disposal.value : 'reject' });
      });
      rule.excludeConditions = [];
      block.querySelectorAll('.sl-simple-condition-row[data-cond-type="exclude"]').forEach(function (row) {
        var input = row.querySelector('.sl-simple-cond-value');
        var disposal = row.querySelector('.sl-simple-cond-disposal');
        var value = input ? input.value.trim() : '';
        if (value) rule.excludeConditions.push({ id: generateId('EC'), field: 'rule', operator: 'custom', value: value, disposalSuggestion: disposal ? disposal.value : 'pass' });
      });

      rule.updatedAt = now();
      if (isNew) labelRules.push(rule);
    });
    saveLabelRules();
  }

  // ── Case CRUD ──
  function openCaseModal(caseId, caseType, tagId) {
    var existing = caseId ? labelCases.filter(function(c){return c.id===caseId;})[0] : null;
    var tag = getSampleTagById(tagId || currentRuleTagId);
    if (!tag) return;
    var selectedType = existing ? existing.contentType || 'text' : 'text';
    var selectedCaseType = existing ? existing.caseType : caseType;

    var html = '<div class="modal-overlay" id="caseModalOverlay" style="display:flex;"><div class="modal" style="max-width:620px;max-height:85vh;overflow-y:auto;"><div class="modal-header">';
    html += '<h3>' + (existing ? '&#32534;&#36753;&#26696;&#20363;' : '&#26032;&#22686;&#26696;&#20363;') + '</h3>';
    html += '<button class="modal-close" id="btnCaseModalClose">&times;</button></div>';
    html += '<div class="form-group"><label class="form-label">&#20869;&#23481;&#31867;&#22411;</label>';
    html += '<select id="caseContentType" class="form-select"><option value="text"' + (selectedType === 'text' ? ' selected' : '') + '>&#25991;&#26412;</option><option value="image"' + (selectedType === 'image' ? ' selected' : '') + '>&#22270;&#29255;</option></select></div>';
    html += '<div id="caseTextFields" style="display:' + (selectedType === 'text' ? '' : 'none') + ';"><div class="form-group"><label class="form-label">&#25991;&#26412;&#20869;&#23481;</label>';
    html += '<textarea id="caseTextContent" class="form-textarea" rows="5">' + escHtml(existing ? existing.textContent || '' : '') + '</textarea></div></div>';
    html += '<div id="caseImageFields" style="display:' + (selectedType === 'image' ? '' : 'none') + ';">';
    html += '<div class="form-group"><label class="form-label">&#22270;&#29255; URL</label><input type="text" id="caseImageUrl" class="form-input" value="' + escHtml(existing ? existing.imageUrl || '' : '') + '" placeholder="&#36755;&#20837;&#22270;&#29255; URL"></div>';
    html += '<div class="form-group"><label class="form-label">&#26412;&#22320;&#22270;&#29255;</label><input type="file" id="caseImageFile" class="form-input" accept="image/*"></div>';
    html += '<div class="sl-case-image-preview" id="caseImagePreview" style="display:' + (existing && existing.imageUrl ? '' : 'none') + ';"><img id="caseImagePreviewImg" src="' + escHtml(existing ? existing.imageUrl || '' : '') + '" alt="&#26696;&#20363;&#22270;&#29255;&#39044;&#35272;"></div>';
    html += '</div>';
    html += '<div class="form-group"><label class="form-label">&#21028;&#26029;&#29702;&#30001;</label><textarea id="caseJudgmentReason" class="form-textarea" rows="3">' + escHtml(existing ? existing.judgmentReason || '' : '') + '</textarea></div>';
    html += '<input type="hidden" id="caseId" value="' + (existing ? existing.id : '') + '">';
    html += '<input type="hidden" id="caseTagId" value="' + tag.id + '">';
    html += '<input type="hidden" id="caseType" value="' + selectedCaseType + '">';
    html += '<div class="form-actions"><button class="btn btn-primary" id="btnCaseSave">&#20445;&#23384;</button><button class="btn btn-secondary" id="btnCaseCancel">&#21462;&#28040;</button></div>';
    html += '</div></div>';

    var overlay = document.createElement('div');
    overlay.innerHTML = html;
    document.body.appendChild(overlay.firstElementChild);
    document.getElementById('caseModalOverlay').addEventListener('click', function(e){if(e.target===this)closeCaseModal();});
    document.getElementById('btnCaseModalClose').addEventListener('click', closeCaseModal);
    document.getElementById('btnCaseCancel').addEventListener('click', closeCaseModal);
    document.getElementById('caseContentType').addEventListener('change', function(){
      var isText = this.value === 'text';
      document.getElementById('caseTextFields').style.display = isText ? '' : 'none';
      document.getElementById('caseImageFields').style.display = isText ? 'none' : '';
    });
    document.getElementById('caseImageUrl').addEventListener('input', updateCaseImagePreview);
    document.getElementById('caseImageFile').addEventListener('change', handleCaseImageFile);
    document.getElementById('btnCaseSave').addEventListener('click', saveCase);
  }

  function closeCaseModal() {
    var overlay = document.getElementById('caseModalOverlay');
    if (overlay) overlay.remove();
  }

  function updateCaseImagePreview() {
    var urlEl = document.getElementById('caseImageUrl');
    var preview = document.getElementById('caseImagePreview');
    var img = document.getElementById('caseImagePreviewImg');
    if (!urlEl || !preview || !img) return;
    var url = urlEl.value.trim();
    if (!url) {
      preview.style.display = 'none';
      img.removeAttribute('src');
      return;
    }
    img.src = url;
    preview.style.display = '';
  }

  function handleCaseImageFile(e) {
    var file = e.target.files && e.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      var urlEl = document.getElementById('caseImageUrl');
      if (urlEl) urlEl.value = reader.result;
      updateCaseImagePreview();
    };
    reader.readAsDataURL(file);
  }

  function saveCase() {
    var caseId = document.getElementById('caseId').value;
    var tagId = document.getElementById('caseTagId').value;
    var caseType = document.getElementById('caseType').value;
    var contentType = document.getElementById('caseContentType').value;
    var textContent = document.getElementById('caseTextContent').value.trim();
    var imageUrl = document.getElementById('caseImageUrl').value.trim();
    var judgmentReason = document.getElementById('caseJudgmentReason').value.trim();

    if (contentType === 'text' && !textContent) { alert('???????'); return; }
    if (contentType === 'image' && !imageUrl) { alert('???????????? URL'); return; }
    if (!judgmentReason) { alert('???????'); return; }

    var nowStr = now();
    if (caseId) {
      var c = labelCases.filter(function(x){return x.id===caseId;})[0];
      if (c) {
        c.caseType = caseType; c.contentType = contentType; c.textContent = textContent; c.imageUrl = imageUrl;
        c.ocrText = ''; c.judgmentReason = judgmentReason; c.keyEvidence = ''; c.scene = '';
        c.judgmentStatus = caseType === 'positive' ? 'reject' : 'pass'; c.reviewStatus = 'confirmed';
        c.canUseForTraining = true; c.canUseForRag = true; c.updatedAt = nowStr;
      }
    } else {
      labelCases.push({
        id: generateId('CASE'), labelId: tagId, caseType: caseType, contentType: contentType,
        textContent: textContent, imageUrl: imageUrl, ocrText: '',
        judgmentStatus: caseType === 'positive' ? 'reject' : 'pass', reviewStatus: 'confirmed', judgmentReason: judgmentReason,
        keyEvidence: '', scene: '', correctLabelId: null,
        canUseForTraining: true, canUseForRag: true,
        createdBy: null, createdAt: nowStr, updatedAt: nowStr
      });
    }
    saveLabelCases();
    closeCaseModal();
    renderTagRulePanel(currentRuleTagId);
  }

  function deleteCase(caseId) {
    if (!confirm('确定删除此案例吗？')) return;
    labelCases = labelCases.filter(function(c){return c.id!==caseId;});
    saveLabelCases();
    renderTagRulePanel(currentRuleTagId);
  }

  // ── Convert sample to case ──
  function convertSampleToCase(sampleId, tagId) {
    var sample = getSampleById(sampleId);
    if (!sample) return;
    var caseType = confirm('确定将样本设为"正例"吗？\n点击"取消"将设为反例。') ? 'positive' : 'negative';
    labelCases.push({
      id: generateId('CASE'), labelId: tagId, caseType: caseType, contentType: sample.contentType || 'text',
      textContent: sample.content || '', imageUrl: sample.imageUrl || '', ocrText: '',
      judgmentStatus: sample.status || 'reject', reviewStatus: 'pending', judgmentReason: sample.reviewReason || '',
      keyEvidence: '', scene: '', correctLabelId: null,
      canUseForTraining: true, canUseForRag: true,
      createdBy: null, createdAt: now(), updatedAt: now()
    });
    saveLabelCases();
    renderTagRulePanel(currentRuleTagId);
    showToast('样本已转为' + (caseType==='positive'?'正例':'反例') + '，请补充判定理由和关键命中点');
  }

  function openSlTagModal(tagId, parentId) {
    var modal = document.getElementById('slTagModal');
    var form = document.getElementById('slTagForm');
    form.reset();

    if (tagId) {
      // Edit existing
      var tag = getSampleTagById(tagId);
      if (!tag) return;
      document.getElementById('slTagModalTitle').textContent = '编辑标签 - ' + tag.name;
      document.getElementById('slTagId').value = tag.id;
      document.getElementById('slTagParentId').value = tag.parentId || '';
      document.getElementById('slTagLevel').value = tag.level;
      document.getElementById('slTagName').value = tag.name;
      document.getElementById('slTagDesc').value = tag.description || '';
      document.getElementById('slTagPositive').value = '';
      document.getElementById('slTagNegative').value = '';
      var ct = tag.applicableContentTypes;
      document.getElementById('slTagAppType').value = ct && ct.length > 0 ? ct[0] : 'all';
      document.getElementById('slTagStatus').value = tag.status || 'active';
    } else {
      // New
      var parentTag = parentId ? getSampleTagById(parentId) : null;
      var level = parentTag ? parentTag.level + 1 : 1;
      document.getElementById('slTagModalTitle').textContent = parentTag ? '新增子标签 — ' + parentTag.name : '新增一级标签';
      document.getElementById('slTagId').value = '';
      document.getElementById('slTagParentId').value = parentId || '';
      document.getElementById('slTagLevel').value = level;
      document.getElementById('slTagStatus').value = 'active';
    }
    modal.style.display = 'flex';
  }

  function handleSlTagSubmit(e) {
    e.preventDefault();
    var tagId = document.getElementById('slTagId').value;
    var parentId = document.getElementById('slTagParentId').value || null;
    var level = parseInt(document.getElementById('slTagLevel').value) || 1;
    var name = document.getElementById('slTagName').value.trim();
    if (!name) { alert('请输入标签名称'); return; }

    var parentTag = parentId ? getSampleTagById(parentId) : null;
    var path = parentTag ? (parentTag.path || parentTag.name) + '/' + name : name;
    var siblings = sampleTags.filter(function (t) { return (t.parentId || null) === (parentId || null) && t.id !== tagId; });

    var data = {
      name: name,
      code: '',
      level: level,
      parentId: parentId || null,
      path: path,
      description: document.getElementById('slTagDesc').value.trim(),
      applicableContentTypes: [document.getElementById('slTagAppType').value === 'all' ? 'text' : document.getElementById('slTagAppType').value],
      suggestedStatus: 'reject',
      riskLevel: 'medium',
      status: document.getElementById('slTagStatus').value,
      ownerId: null,
      sortOrder: siblings.length
    };

    if (tagId) {
      var tag = getSampleTagById(tagId);
      if (tag) {
        data.code = tag.code || data.code;
        data.sortOrder = typeof tag.sortOrder === 'number' ? tag.sortOrder : data.sortOrder;
        Object.keys(data).forEach(function (k) { tag[k] = data[k]; });
        tag.updatedAt = now();
        updateSampleTagPath(tag.id);
      }
    } else {
      data.id = generateId('STAG');
      data.code = 'TAG_' + Date.now().toString(36).toUpperCase();
      data.createdAt = now();
      data.updatedAt = now();
      sampleTags.push(data);
    }
    saveSampleTags();
    document.getElementById('slTagModal').style.display = 'none';
    renderSampleTags();
    if (currentRuleTagId) showTagDetail(currentRuleTagId);
    // Refresh detail category dropdowns
    if (currentSampleId) {
      renderSampleDetail(currentSampleId);
    }
  }

  function openSlRootTagModal() {
    var old = document.getElementById('slRootTagModal');
    if (old) old.remove();
    var html = '<div class="modal-overlay" id="slRootTagModal" style="display:flex;">';
    html += '<div class="modal sl-tag-action-modal"><div class="modal-header">';
    html += '<h3>&#26032;&#24314;&#19968;&#32423;&#26631;&#31614;</h3>';
    html += '<button class="modal-close" id="btnSlRootTagClose">&times;</button></div>';
    html += '<div class="form-row form-row-tag">';
    html += '<div class="form-group"><label class="form-label" for="slRootTagName">&#19968;&#32423;&#26631;&#31614;&#21517;&#31216; <span class="required">*</span></label>';
    html += '<input type="text" id="slRootTagName" class="form-input" maxlength="50" autocomplete="off"></div>';
    html += '<div class="form-group"><label class="form-label" for="slRootTagValue">&#26631;&#31614;&#20540; <span class="required">*</span></label>';
    html += '<input type="text" id="slRootTagValue" class="form-input" maxlength="80" autocomplete="off"></div>';
    html += '<div class="form-group"><label class="form-label" for="slRootTagDesc">&#26631;&#31614;&#35828;&#26126; <span class="required">*</span></label>';
    html += '<textarea id="slRootTagDesc" class="form-textarea" rows="3" placeholder="&#35831;&#36755;&#20837;&#26631;&#31614;&#35828;&#26126;"></textarea></div>';
    html += '</div>';
    html += '<div class="form-actions">';
    html += '<button type="button" class="btn btn-primary" id="btnSlRootTagSave">&#20445;&#23384;</button>';
    html += '<button type="button" class="btn btn-secondary" id="btnSlRootTagCancel">&#21462;&#28040;</button>';
    html += '</div></div></div>';
    document.body.insertAdjacentHTML('beforeend', html);

    function close() {
      var modal = document.getElementById('slRootTagModal');
      if (modal) modal.remove();
    }
    document.getElementById('btnSlRootTagClose').addEventListener('click', close);
    document.getElementById('btnSlRootTagCancel').addEventListener('click', close);
    document.getElementById('btnSlRootTagSave').addEventListener('click', function () {
      var name = document.getElementById('slRootTagName').value.trim();
      var value = document.getElementById('slRootTagValue').value.trim();
      var desc = document.getElementById('slRootTagDesc').value.trim();
      if (!name) { alert('请填写一级标签名称'); return; }
      if (!value) { alert('请填写标签值'); return; }
      if (!desc) { alert('请填写标签说明'); return; }
      var nameExists = sampleTags.some(function (tag) { return tag.level === 1 && (tag.name || '').trim() === name; });
      if (nameExists) { alert('一级标签名称已存在'); return; }
      var valueKey = value.toLowerCase();
      var valueExists = sampleTags.some(function (tag) { return tag.level === 1 && String(tag.code || '').trim().toLowerCase() === valueKey; });
      if (valueExists) { alert('标签值已存在'); return; }
      var siblings = sampleTags.filter(function (tag) { return tag.level === 1; });
      var newTag = {
        id: generateId('STAG'),
        name: name,
        code: value,
        level: 1,
        parentId: null,
        path: name,
        description: desc,
        applicableContentTypes: ['text', 'image'],
        suggestedStatus: 'reject',
        riskLevel: 'medium',
        status: 'active',
        ownerId: null,
        sortOrder: siblings.length,
        createdAt: now(),
        updatedAt: now()
      };
      sampleTags.push(newTag);
      saveSampleTags();
      close();
      renderSampleTags();
      showTagDetail(newTag.id);
    });
  }

  function openSlTagActionModal(tagId) {
    var tag = getSampleTagById(tagId);
    if (!tag) return;
    var old = document.getElementById('slTagActionModal');
    if (old) old.remove();

    var isL1orL2 = tag.level === 1 || tag.level === 2;
    var childLevel = tag.level + 1;
    var childLabel = childLevel === 2 ? '二级' : '三级';

    var html = '<div class="modal-overlay" id="slTagActionModal" style="display:flex;">';
    html += '<div class="modal sl-tag-action-modal"><div class="modal-header">';
    html += '<h3>标签操作 — ' + escHtml(tag.name) + '</h3>';
    html += '<button class="modal-close" id="btnSlTagActionClose">&times;</button></div>';

    // Edit current tag (3-column row)
    html += '<div class="form-row form-row-tag">';
    html += '<div class="form-group">';
    html += '<label class="form-label" for="slTagActionName">标签名称 <span class="required">*</span></label>';
    html += '<input type="text" id="slTagActionName" class="form-input" maxlength="50" value="' + escHtml(tag.name || '') + '">';
    html += '</div>';
    html += '<div class="form-group">';
    html += '<label class="form-label" for="slTagActionCode">标签值 <span class="required">*</span></label>';
    html += '<input type="text" id="slTagActionCode" class="form-input" maxlength="80" value="' + escHtml(tag.code || '') + '">';
    html += '</div>';
    html += '<div class="form-group">';
    html += '<label class="form-label" for="slTagActionDesc">标签说明 <span class="required">*</span></label>';
    html += '<input type="text" id="slTagActionDesc" class="form-input" maxlength="200" value="' + escHtml(tag.description || '') + '" placeholder="请输入标签说明">';
    html += '</div>';
    html += '</div>';

    // Add child tag section (only for level 1 and 2)
    if (isL1orL2) {
      html += '<div class="sl-action-divider"></div>';
      html += '<div class="sl-action-section-title">添加' + childLabel + '子标签</div>';
      html += '<div id="slActionChildRows">';
      // Row template — first row
      html += '<div class="sl-child-row">';
      html += '<div class="form-row form-row-tag">';
      html += '<div class="form-group">';
      html += '<label class="form-label">子标签名称 <span class="required">*</span></label>';
      html += '<input type="text" class="form-input sl-child-name" maxlength="50" placeholder="请输入' + childLabel + '标签名称" autocomplete="off">';
      html += '</div>';
      html += '<div class="form-group">';
      html += '<label class="form-label">标签值 <span class="required">*</span></label>';
      html += '<input type="text" class="form-input sl-child-value" maxlength="80" placeholder="请输入标签值" autocomplete="off">';
      html += '</div>';
      html += '<div class="form-group">';
      html += '<label class="form-label">标签说明 <span class="required">*</span></label>';
      html += '<input type="text" class="form-input sl-child-desc" maxlength="200" placeholder="请输入标签说明" autocomplete="off">';
      html += '</div>';
      html += '</div>';
      html += '<button type="button" class="sl-child-row-remove-btn" title="移除此行" style="display:none;">&times;</button>';
      html += '</div>';
      html += '</div>';
      html += '<div class="form-actions" style="margin-top:8px;">';
      html += '<button type="button" class="btn btn-sm btn-secondary" id="btnSlAddChildRow">+ 添加一行</button>';
      html += '<button type="button" class="btn btn-primary btn-sm" id="btnSlActionAddChild">批量添加' + childLabel + '子标签</button>';
      html += '<span class="form-hint-inline" id="slActionChildMsg" style="color:var(--success);display:none;"></span>';
      html += '</div>';
    }

    // Action buttons
    html += '<div class="sl-action-divider"></div>';
    html += '<div class="form-actions">';
    html += '<button type="button" class="btn btn-primary" id="btnSlTagActionSave">保存名称</button>';
    html += '<button type="button" class="btn btn-danger" id="btnSlTagActionDelete">删除标签</button>';
    html += '<button type="button" class="btn btn-secondary" id="btnSlTagActionCancel">取消</button>';
    html += '</div></div></div>';
    document.body.insertAdjacentHTML('beforeend', html);

    function close() {
      var modal = document.getElementById('slTagActionModal');
      if (modal) modal.remove();
    }
    document.getElementById('btnSlTagActionClose').addEventListener('click', close);
    document.getElementById('btnSlTagActionCancel').addEventListener('click', close);

    // Save name
    document.getElementById('btnSlTagActionSave').addEventListener('click', function () {
      var name = document.getElementById('slTagActionName').value.trim();
      var code = document.getElementById('slTagActionCode').value.trim();
      var desc = document.getElementById('slTagActionDesc').value.trim();
      if (!name) { alert('请输入标签名称'); return; }
      if (!code) { alert('请输入标签值'); return; }
      if (!desc) { alert('请输入标签说明'); return; }
      tag.name = name;
      tag.code = code;
      tag.description = desc;
      tag.updatedAt = now();
      updateSampleTagPath(tag.id);
      saveSampleTags();
      close();
      renderSampleTags();
      showTagDetail(tag.id);
    });

    // Delete
    document.getElementById('btnSlTagActionDelete').addEventListener('click', function () {
      close();
      handleSlTagDelete(tag.id);
    });

    // Add child tag — batch
    if (isL1orL2) {
      // Helper: collect rows from DOM
      function getChildRows() {
        var container = document.getElementById('slActionChildRows');
        return container ? container.querySelectorAll('.sl-child-row') : [];
      }

      // Build a single row element
      function createChildRow() {
        var row = document.createElement('div');
        row.className = 'sl-child-row';
        row.innerHTML = '<div class="form-row form-row-tag">'
          + '<div class="form-group">'
          + '<label class="form-label">子标签名称 <span class="required">*</span></label>'
          + '<input type="text" class="form-input sl-child-name" maxlength="50" placeholder="请输入' + childLabel + '标签名称" autocomplete="off">'
          + '</div>'
          + '<div class="form-group">'
          + '<label class="form-label">标签值 <span class="required">*</span></label>'
          + '<input type="text" class="form-input sl-child-value" maxlength="80" placeholder="请输入标签值" autocomplete="off">'
          + '</div>'
          + '<div class="form-group">'
          + '<label class="form-label">标签说明 <span class="required">*</span></label>'
          + '<input type="text" class="form-input sl-child-desc" maxlength="200" placeholder="请输入标签说明" autocomplete="off">'
          + '</div>'
          + '</div>'
          + '<button type="button" class="sl-child-row-remove-btn" title="移除此行">&times;</button>';
        var btn = row.querySelector('.sl-child-row-remove-btn');
        btn.addEventListener('click', function () {
          var rows = getChildRows();
          if (rows.length <= 1) return;
          row.remove();
          updateRemoveButtons();
        });
        return row;
      }

      function updateRemoveButtons() {
        var rows = getChildRows();
        rows.forEach(function (r) {
          var btn = r.querySelector('.sl-child-row-remove-btn');
          if (btn) btn.style.display = rows.length <= 1 ? 'none' : '';
        });
      }

      // Add row button
      document.getElementById('btnSlAddChildRow').addEventListener('click', function () {
        var container = document.getElementById('slActionChildRows');
        container.appendChild(createChildRow());
        updateRemoveButtons();
      });

      // Wire remove button on initial row (now visible when more than 1 row)
      var initialRemoveBtn = document.querySelector('#slActionChildRows .sl-child-row-remove-btn');
      if (initialRemoveBtn) {
        initialRemoveBtn.addEventListener('click', function () {
          var rows = getChildRows();
          if (rows.length <= 1) return;
          initialRemoveBtn.closest('.sl-child-row').remove();
          updateRemoveButtons();
        });
      }

      // Batch add handler
      document.getElementById('btnSlActionAddChild').addEventListener('click', function () {
        var msgEl = document.getElementById('slActionChildMsg');
        var rows = getChildRows();
        var toCreate = [];
        var errors = [];
        var siblings = sampleTags.filter(function (t) { return (t.parentId || null) === tagId; });
        var existingCodes = {};
        sampleTags.forEach(function (t) { existingCodes[String(t.code || '').trim().toLowerCase()] = true; });
        var existingNames = {};
        siblings.forEach(function (t) { existingNames[(t.name || '').trim()] = true; });

        // Also track names/values within this batch to avoid internal duplicates
        var batchNames = {};
        var batchCodes = {};

        for (var i = 0; i < rows.length; i++) {
          var row = rows[i];
          var name = (row.querySelector('.sl-child-name') || {}).value;
          var value = (row.querySelector('.sl-child-value') || {}).value;
          var desc = (row.querySelector('.sl-child-desc') || {}).value;
          name = name ? name.trim() : '';
          value = value ? value.trim() : '';
          desc = desc ? desc.trim() : '';

          // Skip completely empty rows
          if (!name && !value && !desc) continue;

          if (!name) { errors.push('第' + (i + 1) + '行：请填写子标签名称'); continue; }
          if (!value) { errors.push('第' + (i + 1) + '行：请填写标签值'); continue; }
          if (!desc) { errors.push('第' + (i + 1) + '行：请填写标签说明'); continue; }

          if (existingNames[name] || batchNames[name]) { errors.push('第' + (i + 1) + '行：子标签名称「' + name + '」已存在'); continue; }
          var valueKey = value.toLowerCase();
          if (existingCodes[valueKey] || batchCodes[valueKey]) { errors.push('第' + (i + 1) + '行：标签值「' + value + '」已存在'); continue; }

          batchNames[name] = true;
          batchCodes[valueKey] = true;
          toCreate.push({ name: name, value: value, desc: desc });
        }

        if (errors.length > 0) {
          msgEl.style.display = 'inline';
          msgEl.style.color = 'var(--danger)';
          msgEl.textContent = errors.join('；');
          return;
        }

        if (toCreate.length === 0) {
          msgEl.style.display = 'inline';
          msgEl.style.color = 'var(--danger)';
          msgEl.textContent = '请至少填写一行子标签';
          return;
        }

        // Create all child tags
        var childSiblings = sampleTags.filter(function (t) { return t.parentId === tagId; });
        var sortBase = childSiblings.length;
        toCreate.forEach(function (item, idx) {
          var newChild = {
            id: generateId('STAG'),
            name: item.name,
            code: item.value,
            level: childLevel,
            parentId: tagId,
            path: (tag.path || tag.name) + '/' + item.name,
            description: item.desc,
            applicableContentTypes: tag.applicableContentTypes || ['text', 'image'],
            suggestedStatus: 'reject',
            riskLevel: 'medium',
            status: 'active',
            ownerId: null,
            sortOrder: sortBase + idx,
            createdAt: now(),
            updatedAt: now()
          };
          sampleTags.push(newChild);
        });
        saveSampleTags();

        // Expand parent and refresh tree
        slExpandedTagIds[tagId] = true;
        renderSampleTags();
        showTagDetail(tag.id);

        // Show success and clear all inputs
        msgEl.style.display = 'inline';
        msgEl.style.color = 'var(--success)';
        msgEl.textContent = '已成功添加 ' + toCreate.length + ' 个' + childLabel + '子标签';

        // Clear all rows back to just one empty row
        var container = document.getElementById('slActionChildRows');
        container.innerHTML = '';
        var newRow = createChildRow();
        var newRemoveBtn = newRow.querySelector('.sl-child-row-remove-btn');
        if (newRemoveBtn) {
          newRemoveBtn.style.display = 'none';
          newRemoveBtn.addEventListener('click', function () {
            var rows = getChildRows();
            if (rows.length <= 1) return;
            newRow.remove();
            updateRemoveButtons();
          });
        }
        container.appendChild(newRow);
      });
    }
  }

  function moveSampleTagOrder(tagId, direction) {
    var tag = getSampleTagById(tagId);
    if (!tag) return;
    var siblings = getSampleSiblingTags(tag);
    siblings.forEach(function (item, index) { item.sortOrder = index; });
    var index = siblings.findIndex(function (item) { return item.id === tagId; });
    var targetIndex = direction === 'up' ? index - 1 : index + 1;
    if (index < 0 || targetIndex < 0 || targetIndex >= siblings.length) return;
    var temp = siblings[index].sortOrder;
    siblings[index].sortOrder = siblings[targetIndex].sortOrder;
    siblings[targetIndex].sortOrder = temp;
    saveSampleTags();
    renderSampleTags();
    showTagDetail(tagId);
  }

  function openSlTagMoveModal(tagId) {
    var tag = getSampleTagById(tagId);
    if (!tag) return;
    if (tag.level === 1) {
      alert('一级标签通过上移/下移调整顺序。');
      return;
    }
    var parentLevel = tag.level - 1;
    var parentOptions = sampleTags
      .filter(function (item) { return item.level === parentLevel && item.id !== tag.id; })
      .sort(function (a, b) { return (a.sortOrder || 0) - (b.sortOrder || 0); });
    var old = document.getElementById('slTagMoveModal');
    if (old) old.remove();
    var html = '<div class="modal-overlay" id="slTagMoveModal" style="display:flex;">';
    html += '<div class="modal"><div class="modal-header">';
    html += '<h3>移动标签 - ' + escHtml(tag.name) + '</h3>';
    html += '<button class="modal-close" id="btnSlTagMoveClose">&times;</button></div>';
    html += '<div class="form-group"><label class="form-label" for="slTagMoveParent">目标父级标签</label>';
    html += '<select id="slTagMoveParent" class="form-select">';
    parentOptions.forEach(function (parent) {
      html += '<option value="' + parent.id + '"' + (parent.id === tag.parentId ? ' selected' : '') + '>' + escHtml(parent.path || parent.name) + '</option>';
    });
    html += '</select></div><div class="form-actions">';
    html += '<button type="button" class="btn btn-primary" id="btnSlTagMoveSubmit">确认移动</button>';
    html += '<button type="button" class="btn btn-secondary" id="btnSlTagMoveCancel">取消</button>';
    html += '</div></div></div>';
    document.body.insertAdjacentHTML('beforeend', html);

    function close() {
      var modal = document.getElementById('slTagMoveModal');
      if (modal) modal.remove();
    }
    document.getElementById('btnSlTagMoveClose').addEventListener('click', close);
    document.getElementById('btnSlTagMoveCancel').addEventListener('click', close);
    document.getElementById('btnSlTagMoveSubmit').addEventListener('click', function () {
      var parentId = document.getElementById('slTagMoveParent').value;
      if (!parentId || parentId === tag.parentId) { close(); return; }
      var newParent = getSampleTagById(parentId);
      if (!newParent || newParent.level !== parentLevel) return;
      tag.parentId = parentId;
      tag.sortOrder = getSampleChildTags(parentId).length;
      updateSampleTagPath(tag.id);
      slExpandedTagIds[parentId] = true;
      saveSampleTags();
      close();
      renderSampleTags();
      showTagDetail(tag.id);
    });
  }

  function handleSlTagDelete(tagId) {
    var tag = getSampleTagById(tagId);
    if (!tag) return;
    var childIds = getSampleDescendantTagIds(tagId);
    var deleteIds = [tagId].concat(childIds);
    var childCount = childIds.length;
    var sampleCount = getSampleTagSampleCount(tagId);
    var msg = '确定删除标签 "' + tag.name + '" 吗？';
    if (childCount > 0) msg += '\n该标签下有 ' + childCount + ' 个子标签将被一并删除。';
    if (sampleCount > 0) msg += '\n有 ' + sampleCount + ' 条样本关联此标签。';
    if (!confirm(msg)) return;

    sampleTags = sampleTags.filter(function (t) { return deleteIds.indexOf(t.id) === -1; });
    sampleLibrary.forEach(function (sample) {
      sample.tagIds = (sample.tagIds || []).filter(function (id) { return deleteIds.indexOf(id) === -1; });
      if (deleteIds.indexOf(sample.categoryId) !== -1) sample.categoryId = null;
      sample.updatedAt = now();
    });
    labelRules = labelRules.filter(function (rule) { return deleteIds.indexOf(rule.labelId) === -1; });
    labelCases = labelCases.filter(function (item) { return deleteIds.indexOf(item.labelId) === -1; });
    labelVersions = labelVersions.filter(function (item) { return deleteIds.indexOf(item.labelId) === -1; });
    saveSampleTags();
    saveSampleLibrary();
    saveLabelRules();
    saveLabelCases();
    saveLabelVersions();
    renderSampleTags();
    currentRuleTagId = null;
    document.getElementById('slTagEditPanel').innerHTML = '<h3 class="sl-tag-edit-title">选择标签查看或编辑</h3><p class="form-hint">点击左侧标签节点可查看详情</p>';
  }

  // ── Tag Rule Panel: Conditions (DOM manipulation, saved via collectRuleSettings) ──
  function addHitCondition() {
    var ct = currentRuleContentType;
    var html = renderConditionRow('hit', currentRuleTagId, { field: 'content', operator: 'contains', value: '' }, 0, ct);
    var list = document.getElementById('slHitCondList');
    if (list) list.insertAdjacentHTML('beforeend', html);
  }

  function removeHitCondition(btn) {
    var row = btn.closest('.sl-condition-row');
    if (row) row.remove();
  }

  function addExcludeCondition() {
    var ct = currentRuleContentType;
    var html = renderConditionRow('exc', currentRuleTagId, { field: 'content', operator: 'contains', value: '' }, 0, ct);
    var list = document.getElementById('slExcCondList');
    if (list) list.insertAdjacentHTML('beforeend', html);
  }

  function removeExcludeCondition(btn) {
    var row = btn.closest('.sl-condition-row');
    if (row) row.remove();
  }

  function addSimpleCondition(config) {
    var parts = (config || '').split('|');
    var contentType = parts[0] || 'text';
    var type = parts[1] || 'hit';
    var list = document.querySelector('[data-simple-cond-list="' + contentType + '|' + type + '"]');
    if (list) list.insertAdjacentHTML('beforeend', renderSimpleConditionRow(contentType, type, { value: '' }));
  }

  function removeSimpleCondition(btn) {
    var row = btn.closest('.sl-simple-condition-row');
    if (row) row.remove();
  }

  function saveTagRules(tagId) {
    var tag = getSampleTagById(tagId);
    if (!tag) return;
    // Collect description
    var descEl = document.getElementById('slRuleDesc');
    if (descEl) tag.description = descEl.value.trim();

    // Collect hit conditions from DOM
    var hitRows = document.querySelectorAll('#slHitCondList .sl-condition-row');
    tag.hitConditions = [];
    hitRows.forEach(function (row) {
      var fieldEl = row.querySelector('.sl-cond-field');
      var opEl = row.querySelector('.sl-cond-op');
      var valEl = row.querySelector('.sl-cond-value');
      if (fieldEl && opEl && valEl) {
        tag.hitConditions.push({ id: generateId('HC'), field: fieldEl.value, operator: opEl.value, value: valEl.value.trim() });
      }
    });

    // Collect exclude conditions from DOM
    var excRows = document.querySelectorAll('#slExcCondList .sl-condition-row');
    tag.excludeConditions = [];
    excRows.forEach(function (row) {
      var fieldEl = row.querySelector('.sl-cond-field');
      var opEl = row.querySelector('.sl-cond-op');
      var valEl = row.querySelector('.sl-cond-value');
      if (fieldEl && opEl && valEl) {
        tag.excludeConditions.push({ id: generateId('EC'), field: fieldEl.value, operator: opEl.value, value: valEl.value.trim() });
      }
    });

    saveSampleTags();
    renderTagRulePanel(tagId);
  }

  // ── Datasets ─────────────────────────────────────────────────────
  function renderSampleDatasets() {
    var tbody = document.getElementById('slDatasetTableBody');
    if (sampleDatasets.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="table-empty">暂无数据集</td></tr>';
    } else {
      tbody.innerHTML = sampleDatasets.map(function (ds) {
        return '<tr>' +
          '<td><a class="link" data-action="sl-dataset-view" data-id="' + ds.id + '" href="#">' + ds.name + '</a></td>' +
          '<td>' + slDatasetTypeLabel(ds.type) + '</td>' +
          '<td>' + (ds.sampleIds ? ds.sampleIds.length : 0) + '</td>' +
          '<td>' + formatTime(ds.createdAt) + '</td>' +
          '<td>' +
            '<a class="link" data-action="sl-dataset-edit" data-id="' + ds.id + '" href="#">编辑</a> ' +
            '<a class="link" data-action="sl-dataset-delete" data-id="' + ds.id + '" href="#">删除</a>' +
          '</td></tr>';
      }).join('');
    }
  }

  function openSlDatasetModal(datasetId) {
    var modal = document.getElementById('slDatasetModal');
    var form = document.getElementById('slDatasetForm');
    form.reset();

    if (datasetId) {
      var ds = sampleDatasets.filter(function (d) { return d.id === datasetId; })[0];
      if (!ds) return;
      document.getElementById('slDatasetModalTitle').textContent = '编辑数据集';
      document.getElementById('slDatasetId').value = ds.id;
      document.getElementById('slDatasetName').value = ds.name;
      document.getElementById('slDatasetType').value = ds.type;
      renderSlSamplePicker(ds.sampleIds || []);
    } else {
      document.getElementById('slDatasetModalTitle').textContent = '新建数据集';
      document.getElementById('slDatasetId').value = '';
      renderSlSamplePicker([]);
    }
    modal.style.display = 'flex';
  }

  function renderSlSamplePicker(selectedIds) {
    var picker = document.getElementById('slSamplePicker');
    if (!picker) return;
    picker.innerHTML = '<div class="sl-picker-list">' +
      sampleLibrary.map(function (s) {
        var checked = selectedIds.indexOf(s.id) !== -1;
        return '<label class="sl-picker-item"><input type="checkbox" value="' + s.id + '"' + (checked ? ' checked' : '') + '>' +
          '<span>' + s.id + '</span> <span class="text-muted">' + ((s.title || s.content || '').substring(0, 30)) + '</span></label>';
      }).join('') +
      '</div>';
  }

  function handleSlDatasetSubmit(e) {
    e.preventDefault();
    var datasetId = document.getElementById('slDatasetId').value;
    var name = document.getElementById('slDatasetName').value.trim();
    var type = document.getElementById('slDatasetType').value;
    if (!name) { alert('请输入数据集名称'); return; }

    var sampleIds = [];
    document.querySelectorAll('#slSamplePicker input:checked').forEach(function (cb) { sampleIds.push(cb.value); });

    if (datasetId) {
      var ds = sampleDatasets.filter(function (d) { return d.id === datasetId; })[0];
      if (ds) { ds.name = name; ds.type = type; ds.sampleIds = sampleIds; }
    } else {
      sampleDatasets.push({ id: generateId('DS'), name: name, type: type, sampleIds: sampleIds, createdAt: now() });
    }
    saveSampleDatasets();
    document.getElementById('slDatasetModal').style.display = 'none';
    renderSampleDatasets();
  }

  // ── Knowledge Base ───────────────────────────────────────────────
  function renderSampleKnowledge() {
    var statusFilter = document.getElementById('slKbFilterStatus') ? document.getElementById('slKbFilterStatus').value : '';
    var filtered = sampleKnowledge.slice();
    if (statusFilter) filtered = filtered.filter(function (k) { return k.status === statusFilter; });

    var tbody = document.getElementById('slKnowledgeTableBody');
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="table-empty">暂无知识块</td></tr>';
    } else {
      tbody.innerHTML = filtered.map(function (k) {
        var tag = getSampleTagById(k.tagId);
        return '<tr>' +
          '<td><a class="link" data-action="sl-knowledge-edit" data-id="' + k.id + '" href="#">' + k.title + '</a></td>' +
          '<td>' + (tag ? tag.name : '-') + '</td>' +
          '<td>v' + (k.version || 1) + '</td>' +
          '<td>' + slKnowledgeStatusBadge(k.status) + '</td>' +
          '<td>' + formatTime(k.updatedAt) + '</td>' +
          '<td>' +
            '<a class="link" data-action="sl-knowledge-edit" data-id="' + k.id + '" href="#">编辑</a> ' +
            (k.status === 'draft' ? '<a class="link" data-action="sl-knowledge-publish" data-id="' + k.id + '" href="#">发布</a> ' : '') +
            (k.status === 'published' ? '<a class="link" data-action="sl-knowledge-rollback" data-id="' + k.id + '" href="#">回滚</a> ' : '') +
            '<a class="link" data-action="sl-knowledge-delete" data-id="' + k.id + '" href="#">删除</a>' +
          '</td></tr>';
      }).join('');
    }

    // Populate tag select in modal
    var tagSelect = document.getElementById('slKnowledgeTag');
    if (tagSelect) {
      tagSelect.innerHTML = '<option value="">无</option>';
      sampleTags.filter(function (t) { return t.status === 'enabled'; }).forEach(function (t) {
        var prefix = t.level === 1 ? '' : (t.level === 2 ? '  ' : '    ');
        tagSelect.innerHTML += '<option value="' + t.id + '">' + prefix + t.name + '</option>';
      });
    }
  }

  function openSlKnowledgeModal(knowledgeId) {
    var modal = document.getElementById('slKnowledgeModal');
    var form = document.getElementById('slKnowledgeForm');
    form.reset();

    if (knowledgeId) {
      var k = sampleKnowledge.filter(function (kb) { return kb.id === knowledgeId; })[0];
      if (!k) return;
      document.getElementById('slKnowledgeModalTitle').textContent = '编辑知识块';
      document.getElementById('slKnowledgeId').value = k.id;
      document.getElementById('slKnowledgeTitle').value = k.title || '';
      document.getElementById('slKnowledgeTag').value = k.tagId || '';
      document.getElementById('slKnowledgeContent').value = k.content || '';
      document.getElementById('btnSlKnowledgePublish').style.display = k.status === 'draft' ? '' : 'none';
    } else {
      document.getElementById('slKnowledgeModalTitle').textContent = '新建知识块';
      document.getElementById('slKnowledgeId').value = '';
      document.getElementById('btnSlKnowledgePublish').style.display = '';
    }
    renderSampleKnowledge(); // refresh tag select
    modal.style.display = 'flex';
  }

  function handleSlKnowledgeSave(statusOverride) {
    var kId = document.getElementById('slKnowledgeId').value;
    var title = document.getElementById('slKnowledgeTitle').value.trim();
    var tagId = document.getElementById('slKnowledgeTag').value || null;
    var content = document.getElementById('slKnowledgeContent').value.trim();
    if (!title) { alert('请输入标题'); return; }
    if (!content) { alert('请输入知识内容'); return; }

    var nowStr = now();
    if (kId) {
      var k = sampleKnowledge.filter(function (kb) { return kb.id === kId; })[0];
      if (k) {
        // Save previous version if publishing
        if (statusOverride === 'published' && k.status === 'draft') {
          k.versions = k.versions || [];
          k.versions.push({ title: k.title, content: k.content, tagId: k.tagId, version: k.version || 1, time: k.updatedAt || nowStr });
          k.version = (k.version || 1) + 1;
        }
        k.title = title;
        k.tagId = tagId;
        k.content = content;
        k.status = statusOverride || 'draft';
        k.updatedAt = nowStr;
      }
    } else {
      sampleKnowledge.push({
        id: generateId('KN'),
        title: title,
        content: content,
        tagId: tagId,
        version: 1,
        status: statusOverride || 'draft',
        versions: [],
        createdAt: nowStr,
        updatedAt: nowStr
      });
    }
    saveSampleKnowledge();
    document.getElementById('slKnowledgeModal').style.display = 'none';
    renderSampleKnowledge();
  }

  function handleSlKnowledgePublish(kId) {
    var k = sampleKnowledge.filter(function (kb) { return kb.id === kId; })[0];
    if (!k) return;
    if (!confirm('确定发布知识块 "' + k.title + '" 吗？')) return;

    // Save version and publish
    k.versions = k.versions || [];
    k.versions.push({ title: k.title, content: k.content, tagId: k.tagId, version: k.version || 1, time: k.updatedAt || now() });
    k.version = (k.version || 1) + 1;
    k.status = 'published';
    k.updatedAt = now();
    saveSampleKnowledge();
    renderSampleKnowledge();
  }

  function handleSlKnowledgeRollback(kId) {
    var k = sampleKnowledge.filter(function (kb) { return kb.id === kId; })[0];
    if (!k || !k.versions || k.versions.length === 0) { alert('没有可回滚的版本'); return; }
    var prev = k.versions[k.versions.length - 1];
    if (!confirm('确定回滚到 v' + prev.version + ' 版本吗？当前内容将被替换。')) return;
    k.title = prev.title;
    k.content = prev.content;
    k.tagId = prev.tagId;
    k.version = prev.version;
    k.status = 'published';
    k.updatedAt = now();
    k.versions.pop();
    saveSampleKnowledge();
    renderSampleKnowledge();
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

      document.getElementById('mcmApiKey').value = apiKeysInMemory[mc.id] || '';
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
    var apiKey = (document.getElementById('mcmApiKey').value || '').trim();

    var errors = [];
    if (!configName) errors.push('配置名称不能为空');
    else if (configName.length < 2 || configName.length > 50) errors.push('配置名称长度必须在 2-50 个字符之间');
    if (!baseUrl) errors.push('API Base URL 不能为空');
    if (!apiKey) errors.push('API Key 不能为空');
    if (!modelName) errors.push('模型名称不能为空');
    if (isNaN(temperature) || temperature < 0 || temperature > 1) errors.push('Temperature 必须在 0-1 之间');
    if (isNaN(maxTokens) || maxTokens < 256 || maxTokens > 4096) errors.push('最大输出长度必须在 256-4096 之间');
    if (isNaN(timeout) || timeout < 5 || timeout > 120) errors.push('超时时间必须在 5-120 秒之间');

    if (errors.length > 0) {
      alert('保存失败：\n' + errors.join('\n'));
      return;
    }

    var nowStr = now();
    var mcId = document.getElementById('mcmId').value;

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
        apiKeysInMemory[mcId] = apiKey;
        mc.api_key_masked = maskApiKey(apiKey);
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
      apiKeysInMemory[newMc.id] = apiKey;
      newMc.api_key_masked = maskApiKey(apiKey);
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
    var filtered = promptTemplates.slice();
    filtered.sort(function (a, b) {
      return (b.updatedAt || '').localeCompare(a.updatedAt || '');
    });

    var tbody = document.getElementById('promptTableBody');
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="table-empty">暂无 Prompt 模板，请点击"新建 Prompt"</td></tr>';
    } else {
      tbody.innerHTML = filtered.map(function (p) {
        var typeLabel = p.prompt_type === 'text_audit' ? '文本审核' : p.prompt_type;
        return '<tr>' +
          '<td><strong>' + escHtml(p.prompt_name) + '</strong></td>' +
          '<td>' + typeLabel + '</td>' +
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
  function populateModelSelect(selectId) {
    var modelSelect = document.getElementById(selectId);
    if (!modelSelect) return;
    var curVal = modelSelect.value;

    var enabled = modelConfigs.filter(function (mc) { return mc.status === 'enabled'; });

    var multimodal = enabled.filter(function (mc) { return mc.category !== 'unimodal'; });
    var unimodal = enabled.filter(function (mc) { return mc.category === 'unimodal'; });

    var html = '<option value="">请选择模型配置</option>';
    if (multimodal.length > 0) {
      html += '<optgroup label="多模态">';
      multimodal.forEach(function (mc) {
        html += '<option value="' + mc.id + '">' + escHtml(mc.config_name) + '（' + escHtml(mc.model_name) + '）</option>';
      });
      html += '</optgroup>';
    }
    if (unimodal.length > 0) {
      html += '<optgroup label="单模态">';
      unimodal.forEach(function (mc) {
        html += '<option value="' + mc.id + '">' + escHtml(mc.config_name) + '（' + escHtml(mc.model_name) + '）</option>';
      });
      html += '</optgroup>';
    }
    modelSelect.innerHTML = html;

    var found = enabled.some(function (mc) { return String(mc.id) === String(curVal); });
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

    populateModelSelect('stModelConfig');

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

    populateModelSelect('btModelConfig');

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
    if (annoState.mode === 'imageMulti') {
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
    if (annoState.mode === 'imageMulti') {
      annoState.dataset.forEach(function (item) { if (item.tags) item.tags = []; });
      renderAnnoCurrentPage();
      updateAnnoStatus();
    }
  }

  function updateAnnoStatus() {
    var total = annoState.dataset.length;
    var completed = 0;
    if (annoState.mode === 'imageMulti') {
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
    var isGrid = true;
    if (container) container.className = isGrid ? 'anno-gallery' : 'anno-gallery list-view';

    var html = '';
    for (var i = 0; i < pageData.length; i++) {
      var item = pageData[i];
      var gIdx = annoState.dataset.indexOf(item);
      if (annoState.mode === 'imageMulti') {
        html += renderAnnoImageMultiCard(item, gIdx);
      } else if (annoState.mode === 'imageEval') {
        html += renderAnnoImageEvalCard(item, gIdx);
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
    }
  }

  function switchAnnoMode(mode) {
    annoState.mode = mode;
    annoState.dataset = [];
    annoState.page = 1;

    // Update page title and description per mode
    var titles = { imageMulti: '图片标注', imageEval: '图片评估' };
    var descs = {
      imageMulti: '对图片进行多标签分类标注，支持自定义标签库管理',
      imageEval: '对图片机审结果进行符合/不符合评估，支持填写不符合理由'
    };
    var titleEl = document.getElementById('annoPageTitle');
    var descEl = document.getElementById('annoPageDesc');
    if (titleEl) titleEl.textContent = titles[mode] || mode;
    if (descEl) descEl.textContent = descs[mode] || '';

    // Toggle tag manager visibility
    var tagMgr = document.getElementById('annoTagManager');
    if (tagMgr) tagMgr.style.display = (mode === 'imageMulti') ? 'block' : 'none';

    // Toggle tag count display in status bar (imageEval doesn't need it)
    var tagCountEl = document.getElementById('annoTagCount');
    if (tagCountEl) tagCountEl.parentElement.style.display = (mode === 'imageMulti') ? '' : 'none';

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
      filename = '图片分类.csv';
      downloadAnnoCSV(rows, filename);
    } else if (annoState.mode === 'imageEval') {
      rows = [['图片URL', '机审标签', '审核状态', '不符合理由']];
      annoState.dataset.forEach(function (item) { rows.push([item.url, item.machineTag || '', item.status || '', item.reason || '']); });
      filename = '图片评估.csv';
      downloadAnnoCSV(rows, filename);
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
        var sidebar = document.getElementById('sidebar');
        if (sidebar && sidebar.classList.contains('is-collapsed')) {
          setSidebarCollapsed(false);
          window.setTimeout(function () {
            closeAllMenuParents(parentItem);
            setMenuParentOpen(parentItem, true);
          }, 230);
          return;
        }
        var isOpen = parentItem.classList.contains('is-open');
        closeAllMenuParents(parentItem);
        setMenuParentOpen(parentItem, !isOpen);
        return;
      }
      var topItem = e.target.closest('.menu-item');
      if (topItem && !topItem.classList.contains('menu-parent')) {
        switchMenu(topItem.dataset.menu);
        return;
      }
    });

    document.getElementById('sidebarToggle').addEventListener('click', function () {
      var sidebar = document.getElementById('sidebar');
      setSidebarCollapsed(!sidebar.classList.contains('is-collapsed'));
    });

    (function () {
      setSidebarCollapsed(localStorage.getItem('sidebar_collapsed') === '1');
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

    // ── Comment Labeling Workbench events ──────────────────────────
    // Tag management
    document.getElementById('commentAddTagBtn').addEventListener('click', addCommentTag);
    document.getElementById('commentTagInput').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); addCommentTag(); }
    });
    document.getElementById('commentTagList').addEventListener('click', function (e) {
      var tag = e.target.getAttribute('data-comment-remove-tag');
      if (tag) removeCommentTag(tag);
    });

    // File operations
    document.getElementById('commentDownloadTemplateBtn').addEventListener('click', downloadCommentTemplate);
    document.getElementById('commentExportBtn').addEventListener('click', exportCommentResult);
    document.getElementById('commentClearBtn').addEventListener('click', clearCommentAll);
    document.getElementById('commentFileInput').addEventListener('change', function () {
      if (this.files && this.files[0]) handleCommentFile(this.files[0]);
    });

    // Filters
    document.getElementById('commentSearchInput').addEventListener('input', function () {
      commentState.nextUnlabeledCursor = 0;
      commentState.currentPage = 1;
      renderCommentCards();
    });
    document.getElementById('commentStatusFilter').addEventListener('change', function () {
      commentState.nextUnlabeledCursor = 0;
      commentState.currentPage = 1;
      renderCommentCards();
    });
    document.getElementById('commentTagFilter').addEventListener('change', function () {
      commentState.nextUnlabeledCursor = 0;
      commentState.currentPage = 1;
      renderCommentCards();
    });

    // Jump to next unlabeled
    document.getElementById('commentUnlabeledWrap').addEventListener('click', jumpToNextCommentUnlabeled);

    // Pagination (both top and bottom)
    [document.getElementById('commentTopPagination'), document.getElementById('commentBottomPagination')].forEach(function (el) {
      el.addEventListener('click', function (e) {
        var page = e.target.getAttribute('data-comment-page');
        if (page) changeCommentPage(page);
      });
    });

    // Card container: label selection, clear row, reason textarea
    document.getElementById('commentCardContainer').addEventListener('click', function (e) {
      var lbl = e.target.getAttribute('data-comment-label');
      var clr = e.target.getAttribute('data-comment-clear');
      if (lbl) {
        var parts = lbl.split('|');
        selectCommentLabel(parts[0], parts.slice(1).join('|'));
      }
      if (clr) clearCommentRow(clr);
    });
    document.getElementById('commentCardContainer').addEventListener('input', function (e) {
      var id = e.target.getAttribute('data-comment-reason');
      if (id) updateCommentReason(id);
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

    // ── Sample Library Event Delegation ────────────────────────────

    // Tag tree click delegation (toggle expand)
    document.getElementById('slTagTree').addEventListener('click', function (e) {
      var toggle = e.target.closest('.sl-tree-toggle');
      if (toggle) {
        var tagId = toggle.dataset.tagId;
        slExpandedTagIds[tagId] = !slExpandedTagIds[tagId];
        renderSampleTags();
        var toggledTag = getSampleTagById(tagId);
        if (toggledTag && toggledTag.level === 1) {
          if (slExpandedTagIds[tagId]) {
            renderTagSummaryPanel(tagId);
          } else {
            document.getElementById('slTagEditPanel').innerHTML = '';
          }
        }
        return;
      }
      var menuBtn = e.target.closest('[data-sl-tag-menu]');
      if (menuBtn) { openSlTagActionModal(menuBtn.getAttribute('data-sl-tag-menu')); return; }
      var row = e.target.closest('.sl-tree-row');
      if (row) showTagDetail(row.dataset.tagId);
    });

    // Tag tree search input
    var slTagSearchEl = document.getElementById('slTagSearchInput');
    if (slTagSearchEl) {
      slTagSearchEl.addEventListener('input', function () { renderSampleTags(); });
    }

    // Tag panel — click delegation for tab workspace
    document.getElementById('slTagEditPanel').addEventListener('click', function (e) {
      // Level-3 accordion card toggle
      var l3Toggle = e.target.closest('[data-l3-toggle]');
      if (l3Toggle) {
        e.stopPropagation();
        var cardId = l3Toggle.dataset.l3Toggle;
        slExpandedL3CardId = (slExpandedL3CardId === cardId) ? null : cardId;
        // Find the level-2 parent (walk up from the L3 tag)
        var l3Tag = getSampleTagById(cardId);
        var l2Parent = l3Tag && l3Tag.parentId ? getSampleTagById(l3Tag.parentId) : null;
        if (l2Parent && l2Parent.level === 2) {
          renderL2ChildrenAccordion(l2Parent.id);
        }
        return;
      }

      var btn = e.target.closest('button, a[data-action]');
      if (!btn) return;

      // Tab switching
      if (btn.dataset.ruleTab) { currentRuleTab = btn.dataset.ruleTab; renderTagRulePanel(currentRuleTagId); return; }
      // Content type sub-tab
      if (btn.dataset.ruleCt) { currentRuleContentType = btn.dataset.ruleCt; renderTagRulePanel(currentRuleTagId); return; }

      // Top toolbar
      if (btn.id === 'btnSlNewTag') { openSlRootTagModal(); return; }
      if (btn.dataset.slPanelActions) { openSlTagActionModal(btn.dataset.slPanelActions); return; }
      if (btn.id === 'btnRulePublish') { publishRule(); return; }

      if (btn.dataset.simpleAddCond) { addSimpleCondition(btn.dataset.simpleAddCond); return; }
      if (btn.dataset.action === 'remove-simple-cond') { removeSimpleCondition(btn); return; }

      // Add conditions
      if (btn.id === 'btnAddHitCond') { addHitCondition(); return; }
      if (btn.id === 'btnAddExcCond') { addExcludeCondition(); return; }

      // Remove conditions
      if (btn.dataset.action === 'remove-hit-cond') { removeHitCondition(btn); return; }
      if (btn.dataset.action === 'remove-exc-cond') { removeExcludeCondition(btn); return; }

      // Case management
      if (btn.dataset.action === 'edit-case') { openCaseModal(btn.dataset.id, null, currentRuleTagId); return; }
      if (btn.dataset.action === 'delete-case') { deleteCase(btn.dataset.id); return; }
      if (btn.id === 'btnAddCase') { openCaseModal(null, btn.dataset.caseType, currentRuleTagId); return; }

      // Sample actions within related samples tab
      if (btn.dataset.action === 'sl-sample-to-case') { convertSampleToCase(btn.dataset.sampleId, btn.dataset.tagId); return; }
      if (btn.dataset.action === 'sl-view') { currentSampleId = btn.dataset.id; switchMenu('sample-detail'); return; }
    });

    // Tag panel — Enter for keyword / OCR tag chip input
    document.getElementById('slTagEditPanel').addEventListener('keydown', function (e) {
      if (e.key !== 'Enter') return;
      if (e.target.id === 'slRuleKeywordInput' || e.target.id === 'slRuleOcrInput') {
        e.preventDefault();
        var val = e.target.value.trim();
        if (!val) return;
        var containerId = e.target.id === 'slRuleKeywordInput' ? 'slRuleKeywords' : 'slRuleOcrFeatures';
        var container = document.getElementById(containerId);
        if (container) {
          var chip = document.createElement('span');
          chip.className = 'sl-tag-chip';
          chip.innerHTML = escHtml(val) + '<span class="sl-tag-chip-x">×</span>';
          container.appendChild(chip);
        }
        e.target.value = '';
      }
    });

    // Tag panel — remove keyword / OCR tag chips
    document.getElementById('slTagEditPanel').addEventListener('click', function (e) {
      var chipX = e.target.closest('.sl-tag-chip-x');
      if (chipX) { chipX.parentElement.remove(); return; }
    });

    // Tag panel — level-1 category change updates level-2 dropdown
    document.getElementById('slTagEditPanel').addEventListener('change', function (e) {
      if (e.target.id === 'slBasicCat1') {
        var cat2El = document.getElementById('slBasicCat2');
        if (cat2El) {
          var lvl2 = sampleTags.filter(function(t){return t.level===2 && t.parentId===e.target.value;});
          cat2El.innerHTML = lvl2.length > 0 ? lvl2.map(function(t){return '<option value="'+t.id+'">'+escHtml(t.name)+'</option>';}).join('') : '<option value="">请选择二级标签</option>';
        }
      }
    });

    // New tag button
    document.getElementById('btnSlNewTag').addEventListener('click', function (e) { e.stopPropagation(); openSlRootTagModal(); });

    // Tag modal
    document.getElementById('slTagForm').addEventListener('submit', handleSlTagSubmit);
    document.getElementById('btnSlTagCancel').addEventListener('click', function () { document.getElementById('slTagModal').style.display = 'none'; });
    document.getElementById('btnSlTagModalClose').addEventListener('click', function () { document.getElementById('slTagModal').style.display = 'none'; });

    // Sample list - view/edit actions
    document.getElementById('slSampleTableBody').addEventListener('click', function (e) {
      var link = e.target.closest('a[data-action]');
      if (!link) return;
      e.preventDefault();
      var action = link.dataset.action;
      var id = link.dataset.id;
      if (action === 'sl-view' || action === 'sl-edit') {
        currentSampleId = id;
        switchMenu('sample-detail');
      }
    });

    // Sample list - new sample
    document.getElementById('btnSlNewSample').addEventListener('click', function () {
      var s = {
        id: generateId('SAMP'),
        title: '',
        content: '',
        contentType: 'text',
        status: 'pass',
        categoryId: 'stag_9',
        tagIds: ['stag_9'],
        source: 'manual',
        usage: [],
        reviewReason: '',
        confidence: 0,
        imageUrl: '',
        auditHistory: [],
        createdAt: now(),
        updatedAt: now()
      };
      sampleLibrary.push(s);
      saveSampleLibrary();
      currentSampleId = s.id;
      switchMenu('sample-detail');
    });

    // Sample list - filters
    document.getElementById('slSearchInput').addEventListener('input', function () {
      slListFilter.search = this.value;
      slListPage = 1;
      renderSampleList();
    });
    document.getElementById('slFilterType').addEventListener('change', function () {
      slListFilter.contentType = this.value;
      slListPage = 1;
      renderSampleList();
    });
    document.getElementById('slFilterStatus').addEventListener('change', function () {
      slListFilter.status = this.value;
      slListPage = 1;
      renderSampleList();
    });
    document.getElementById('slFilterCategory').addEventListener('change', function () {
      slListFilter.categoryId = this.value;
      slListPage = 1;
      renderSampleList();
    });

    // Sample detail - back
    document.getElementById('btnSlDetailBack').addEventListener('click', function () {
      currentSampleId = null;
      switchMenu('sample-list');
    });

    // Sample detail - content type change
    document.getElementById('slDetailType').addEventListener('change', function () {
      var isText = this.value === 'text';
      document.getElementById('slDetailTextFields').style.display = isText ? '' : 'none';
      document.getElementById('slDetailImageFields').style.display = isText ? 'none' : '';
    });

    // Sample detail - category change refreshes tag pills
    document.getElementById('slDetailCategory').addEventListener('change', function () {
      var currentTagIds = [];
      document.querySelectorAll('[data-sl-tag-checkbox]:checked').forEach(function (cb) { currentTagIds.push(cb.value); });
      // Remove tags from old category, add new category
      currentTagIds = currentTagIds.filter(function (tid) {
        var t = getSampleTagById(tid);
        return t && t.parentId !== this.value;
      }.bind(this));
      currentTagIds.unshift(this.value);
      renderSlTagPills(currentTagIds, this.value);
    });

    // Sample detail - tag pill clicks
    document.getElementById('slDetailTagPills').addEventListener('change', function (e) {
      var cb = e.target.closest('[data-sl-tag-checkbox]');
      if (!cb) return;
      var pill = cb.closest('.sl-tag-pill');
      if (pill) { pill.classList.toggle('checked', cb.checked); }
    });

    // Sample detail - save
    document.getElementById('slDetailForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var sample = getSampleById(currentSampleId);
      if (!sample) return;
      var isText = document.getElementById('slDetailType').value === 'text';
      sample.contentType = document.getElementById('slDetailType').value;
      sample.status = document.getElementById('slDetailStatus').value;
      sample.categoryId = document.getElementById('slDetailCategory').value;
      sample.source = document.getElementById('slDetailSource').value;
      sample.reviewReason = document.getElementById('slDetailReason').value.trim();
      sample.updatedAt = now();

      if (isText) {
        sample.title = document.getElementById('slDetailTitle').value.trim();
        sample.content = document.getElementById('slDetailText').value.trim();
      } else {
        sample.title = document.getElementById('slDetailImgTitle').value.trim();
        sample.imageUrl = document.getElementById('slDetailImgUrl').value.trim();
      }

      // Collect selected tag IDs
      var tagIds = [];
      document.querySelectorAll('[data-sl-tag-checkbox]:checked').forEach(function (cb) { tagIds.push(cb.value); });
      if (tagIds.indexOf(sample.categoryId) === -1) tagIds.unshift(sample.categoryId);
      sample.tagIds = tagIds;

      sample.auditHistory = sample.auditHistory || [];
      sample.auditHistory.push({ time: now(), action: '编辑保存', detail: '状态: ' + (sample.status === 'pass' ? '通过' : sample.status === 'reject' ? '不通过' : '嫌疑') + ' | 分类: ' + (getSampleTagById(sample.categoryId) || {}).name, operator: '用户' });
      saveSampleLibrary();
      renderSampleDetail(currentSampleId);
    });

    // Sample detail - delete
    document.getElementById('btnSlDelete').addEventListener('click', function () {
      if (!confirm('确定删除该样本吗？此操作不可恢复。')) return;
      sampleLibrary = sampleLibrary.filter(function (s) { return s.id !== currentSampleId; });
      saveSampleLibrary();
      currentSampleId = null;
      switchMenu('sample-list');
    });

    // Dataset table actions
    document.getElementById('slDatasetTableBody').addEventListener('click', function (e) {
      var link = e.target.closest('a[data-action]');
      if (!link) return;
      e.preventDefault();
      var action = link.dataset.action;
      var id = link.dataset.id;
      if (action === 'sl-dataset-view' || action === 'sl-dataset-edit') openSlDatasetModal(id);
      else if (action === 'sl-dataset-delete') {
        if (!confirm('确定删除该数据集吗？')) return;
        sampleDatasets = sampleDatasets.filter(function (d) { return d.id !== id; });
        saveSampleDatasets();
        renderSampleDatasets();
      }
    });

    // New dataset
    document.getElementById('btnSlNewDataset').addEventListener('click', function () { openSlDatasetModal(null); });

    // Dataset modal
    document.getElementById('slDatasetForm').addEventListener('submit', handleSlDatasetSubmit);
    document.getElementById('btnSlDatasetModalClose').addEventListener('click', function () { document.getElementById('slDatasetModal').style.display = 'none'; });

    // Knowledge table actions
    document.getElementById('slKnowledgeTableBody').addEventListener('click', function (e) {
      var link = e.target.closest('a[data-action]');
      if (!link) return;
      e.preventDefault();
      var action = link.dataset.action;
      var id = link.dataset.id;
      if (action === 'sl-knowledge-edit') openSlKnowledgeModal(id);
      else if (action === 'sl-knowledge-publish') handleSlKnowledgePublish(id);
      else if (action === 'sl-knowledge-rollback') handleSlKnowledgeRollback(id);
      else if (action === 'sl-knowledge-delete') {
        if (!confirm('确定删除该知识块吗？')) return;
        sampleKnowledge = sampleKnowledge.filter(function (k) { return k.id !== id; });
        saveSampleKnowledge();
        renderSampleKnowledge();
      }
    });

    // Knowledge filter
    document.getElementById('slKbFilterStatus').addEventListener('change', renderSampleKnowledge);

    // New knowledge
    document.getElementById('btnSlNewKnowledge').addEventListener('click', function () { openSlKnowledgeModal(null); });

    // Knowledge modal
    document.getElementById('slKnowledgeForm').addEventListener('submit', function (e) { e.preventDefault(); handleSlKnowledgeSave(null); });
    document.getElementById('btnSlKnowledgePublish').addEventListener('click', function () { handleSlKnowledgeSave('published'); });
    document.getElementById('btnSlKnowledgeModalClose').addEventListener('click', function () { document.getElementById('slKnowledgeModal').style.display = 'none'; });
  }

  // ── Comment Labeling Workbench ─────────────────────────────────

  var commentState = {
    tags: ['正常', '涉政', '色情', '谩骂', '广告', '违禁', '灌水', '竞品', '其他'],
    rows: [],
    auxHeaders: [],
    nextUnlabeledCursor: 0,
    currentPage: 1,
    pageSize: 20
  };

  var STORAGE_COMMENT_TAGS = 'content_detection_comment_tags';

  function loadCommentTags() {
    try {
      var raw = localStorage.getItem(STORAGE_COMMENT_TAGS);
      if (raw) { var arr = JSON.parse(raw); if (Array.isArray(arr) && arr.length) commentState.tags = arr; }
    } catch (e) { /* use defaults */ }
  }
  function saveCommentTags() {
    localStorage.setItem(STORAGE_COMMENT_TAGS, JSON.stringify(commentState.tags));
  }

  function escComment(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function renderCommentTags() {
    var list = document.getElementById('commentTagList');
    if (!list) return;
    list.innerHTML = commentState.tags.map(function (tag) {
      return '<span class="anno-tag-pill">' + escComment(tag) + '<button data-comment-remove-tag="' + escComment(tag) + '">&times;</button></span>';
    }).join('');
    // Update tag filter dropdown
    var filter = document.getElementById('commentTagFilter');
    if (!filter) return;
    var cur = filter.value;
    filter.innerHTML = '<option value="all">全部标签</option>' + commentState.tags.map(function (t) { return '<option value="' + escComment(t) + '">' + escComment(t) + '</option>'; }).join('');
    filter.value = commentState.tags.indexOf(cur) !== -1 ? cur : 'all';
  }

  function addCommentTag() {
    var input = document.getElementById('commentTagInput');
    if (!input) return;
    var val = input.value.trim();
    if (!val) return;
    if (commentState.tags.indexOf(val) !== -1) return;
    commentState.tags.push(val);
    input.value = '';
    saveCommentTags();
    renderCommentTags();
    renderCommentCards();
  }

  function removeCommentTag(tag) {
    commentState.tags = commentState.tags.filter(function (t) { return t !== tag; });
    saveCommentTags();
    renderCommentTags();
    renderCommentCards();
  }

  function downloadCommentTemplate() {
    if (!window.XLSX) return;
    var rows = [
      ['标题', '评论', '辅助信息1', '辅助信息2', '辅助信息3'],
      ['示例标题：新品发布讨论', '这个功能看起来不错，想试试', '用户等级：普通用户', '来源：社区评论', '发布时间：2026-05-22']
    ];
    var ws = XLSX.utils.aoa_to_sheet(rows);
    ws['!cols'] = [{ wch: 28 }, { wch: 46 }, { wch: 24 }, { wch: 24 }, { wch: 24 }];
    var wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, '评论标注模板');
    XLSX.writeFile(wb, '评论标注模板.xlsx');
  }

  function handleCommentFile(file) {
    if (!file) return;
    if (!/\.(xlsx|xls)$/i.test(file.name)) { alert('请上传 .xlsx 或 .xls 文件'); return; }
    var reader = new FileReader();
    reader.onload = function (e) {
      try {
        var wb = XLSX.read(e.target.result, { type: 'array' });
        var sheet = wb.Sheets[wb.SheetNames[0]];
        var matrix = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });
        parseCommentMatrix(matrix, file.name);
      } catch (err) { alert('Excel 解析失败：' + err.message); }
    };
    reader.readAsArrayBuffer(file);
  }

  function parseCommentMatrix(matrix, fileName) {
    function norm(v) { return String(v == null ? '' : v).trim(); }
    var nonEmpty = matrix.filter(function (r) { return r.some(function (c) { return norm(c); }); });
    if (nonEmpty.length < 2) { alert('Excel 至少需要包含表头和 1 条数据'); return; }

    var headers = nonEmpty[0].map(norm);
    var ti = headers.indexOf('标题');
    var ci = headers.indexOf('评论');
    if (ti === -1 || ci === -1) { alert('模板格式错误：必须包含「标题」「评论」两列'); return; }

    var auxH = headers.filter(function (h, i) { return h && i !== ti && i !== ci; }).slice(0, 3);
    commentState.auxHeaders = auxH;

    commentState.rows = nonEmpty.slice(1).map(function (row, idx) {
      var aux = {};
      auxH.forEach(function (h) {
        var si = headers.indexOf(h);
        aux[h] = norm(row[si]);
      });
      return {
        id: 'CR' + Date.now().toString(36) + idx,
        index: idx + 1,
        title: norm(row[ti]),
        comment: norm(row[ci]),
        aux: aux,
        label: '',
        reason: ''
      };
    }).filter(function (item) { return item.title || item.comment || Object.values(item.aux).some(function (v) { return v; }); });

    commentState.nextUnlabeledCursor = 0;
    commentState.currentPage = 1;
    document.getElementById('commentFileName').textContent = fileName;
    document.getElementById('commentFileInput').value = '';
    renderCommentCards();
  }

  function getCommentFilteredRows() {
    var keyword = (document.getElementById('commentSearchInput').value || '').trim().toLowerCase();
    var status = document.getElementById('commentStatusFilter').value;
    var tag = document.getElementById('commentTagFilter').value;
    return commentState.rows.filter(function (row) {
      var hay = [row.title, row.comment].concat(Object.values(row.aux)).join(' ').toLowerCase();
      var kw = !keyword || hay.indexOf(keyword) !== -1;
      var st = status === 'all' || (status === 'labeled' ? !!row.label : !row.label);
      var tg = tag === 'all' || row.label === tag;
      return kw && st && tg;
    });
  }

  function getCommentPageCount(filtered) {
    return Math.max(1, Math.ceil((filtered || getCommentFilteredRows()).length / commentState.pageSize));
  }

  function renderCommentPagination(filtered) {
    var total = filtered.length;
    var topEl = document.getElementById('commentTopPagination');
    var botEl = document.getElementById('commentBottomPagination');
    if (!commentState.rows.length || !total) {
      topEl.style.display = 'none';
      botEl.style.display = 'none';
      return;
    }
    var pc = getCommentPageCount(filtered);
    var start = (commentState.currentPage - 1) * commentState.pageSize + 1;
    var end = Math.min(commentState.currentPage * commentState.pageSize, total);
    var pages = buildCommentPageNumbers(commentState.currentPage, pc);
    var btns = pages.map(function (p) {
      return p === '...'
        ? '<span class="page-info">...</span>'
        : '<button class="' + (p === commentState.currentPage ? 'active' : '') + '" data-comment-page="' + p + '">' + p + '</button>';
    }).join('');
    var html = '<button ' + (commentState.currentPage === 1 ? 'disabled' : '') + ' data-comment-page="prev">上一页</button>'
      + btns
      + '<button ' + (commentState.currentPage === pc ? 'disabled' : '') + ' data-comment-page="next">下一页</button>'
      + '<span class="page-info">' + start + '-' + end + ' / 共 ' + total + ' 条 ' + pc + ' 页</span>';
    topEl.innerHTML = html;
    botEl.innerHTML = html;
    topEl.style.display = 'flex';
    botEl.style.display = pc > 1 ? 'flex' : 'none';
  }

  function buildCommentPageNumbers(page, total) {
    if (total <= 7) { var arr = []; for (var i = 1; i <= total; i++) arr.push(i); return arr; }
    var pages = [1];
    if (page > 4) pages.push('...');
    var s = Math.max(2, page - 1);
    var e = Math.min(total - 1, page + 1);
    for (var i = s; i <= e; i++) pages.push(i);
    if (page < total - 3) pages.push('...');
    pages.push(total);
    return pages;
  }

  function changeCommentPage(target) {
    var filtered = getCommentFilteredRows();
    var pc = getCommentPageCount(filtered);
    if (target === 'prev') commentState.currentPage--;
    else if (target === 'next') commentState.currentPage++;
    else commentState.currentPage = Number(target);
    commentState.currentPage = Math.max(1, Math.min(commentState.currentPage, pc));
    renderCommentCards();
    scrollCommentPageToFirstCard();
  }

  function scrollCommentPageToFirstCard() {
    requestAnimationFrame(function () {
      var firstCard = document.querySelector('#commentCardContainer .comment-card-item');
      var target = firstCard || document.getElementById('commentCardContainer');
      if (!target) return;
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  function renderCommentCards() {
    updateCommentStats();

    var container = document.getElementById('commentCardContainer');
    if (!commentState.rows.length) {
      document.getElementById('commentTopPagination').style.display = 'none';
      document.getElementById('commentBottomPagination').style.display = 'none';
      container.innerHTML = '<div class="comment-empty"><strong>暂无数据</strong>上传 Excel 后，这里会以卡片形式展示标题、评论和辅助信息。</div>';
      return;
    }

    var filtered = getCommentFilteredRows();
    if (!filtered.length) {
      renderCommentPagination(filtered);
      container.innerHTML = '<div class="comment-empty"><strong>没有匹配结果</strong>请调整搜索关键词、标注状态或标签筛选条件。</div>';
      return;
    }

    var pc = getCommentPageCount(filtered);
    if (commentState.currentPage > pc) commentState.currentPage = pc;
    var start = (commentState.currentPage - 1) * commentState.pageSize;
    var pageRows = filtered.slice(start, start + commentState.pageSize);

    renderCommentPagination(filtered);
    container.innerHTML = '<div class="comment-card-list">' + pageRows.map(renderCommentCard).join('') + '</div>';
  }

  function renderCommentCard(row) {
    var auxEntries = Object.entries(row.aux).filter(function (e) { return String(e[1] || '').trim(); });
    var auxHtml = auxEntries.map(function (e) {
      return '<div class="comment-aux-box"><div class="comment-field-label">' + escComment(e[0]) + '</div><div class="comment-field-value">' + escComment(e[1]) + '</div></div>';
    }).join('');
    var hasAux = auxEntries.length > 0;

    var labelBtns = commentState.tags.map(function (tag) {
      return '<button class="comment-label-btn' + (row.label === tag ? ' active' : '') + '" data-comment-label="' + row.id + '|' + escComment(tag) + '">' + escComment(tag) + '</button>';
    }).join('');

    var isLabeled = !!row.label;

    return '<div class="comment-card-item" data-comment-id="' + row.id + '">'
      + '<div class="comment-card-head">'
        + '<span class="comment-card-index' + (isLabeled ? ' is-labeled' : '') + '">第 ' + row.index + ' 条' + (row.label ? ' · 已标注：' + escComment(row.label) : ' · 未标注') + '</span>'
        + '<button class="btn btn-sm btn-secondary" data-comment-clear="' + row.id + '">清空标注</button>'
      + '</div>'
      + '<div class="comment-card-body' + (hasAux ? '' : ' no-aux') + '">'
        + '<div class="comment-main-col">'
          + '<div class="comment-field-box title-box"><div class="comment-field-label">标题</div><div class="comment-field-value">' + escComment(row.title || '未填写标题') + '</div></div>'
          + '<div class="comment-field-box comment-box"><div class="comment-field-label">评论</div><div class="comment-field-value">' + escComment(row.comment || '未填写评论') + '</div></div>'
        + '</div>'
        + (hasAux ? '<div class="comment-aux-col">' + auxHtml + '</div>' : '')
      + '</div>'
      + '<div class="comment-annotation-row">'
        + '<div class="comment-label-choices">' + (labelBtns || '<span style="color:var(--text-muted);font-size:13px;">请先在标签管理中添加标签</span>') + '</div>'
        + '<textarea class="comment-reason-textarea" data-comment-reason="' + row.id + '" placeholder="选填：填写标注理由">' + escComment(row.reason) + '</textarea>'
      + '</div>'
    + '</div>';
  }

  function updateCommentStats() {
    var labeled = commentState.rows.filter(function (r) { return r.label; }).length;
    var total = commentState.rows.length;
    var totalEl = document.getElementById('commentTotalCount');
    var labeledEl = document.getElementById('commentLabeledCount');
    var unlabeledEl = document.getElementById('commentUnlabeledCount');
    if (totalEl) totalEl.textContent = total;
    if (labeledEl) labeledEl.textContent = labeled;
    if (unlabeledEl) unlabeledEl.textContent = total - labeled;
  }

  function refreshCommentCardDOM(id) {
    var row = commentState.rows.find(function (r) { return r.id === id; });
    if (!row) return;
    var card = document.querySelector('[data-comment-id="' + id + '"]');
    if (!card) return;

    // Update status badge
    var badge = card.querySelector('.comment-card-index');
    if (badge) {
      badge.textContent = '第 ' + row.index + ' 条' + (row.label ? ' · 已标注：' + row.label : ' · 未标注');
      badge.classList.toggle('is-labeled', !!row.label);
    }

    // Update label button active states
    var buttons = card.querySelectorAll('.comment-label-btn');
    buttons.forEach(function (btn) {
      var lbl = btn.getAttribute('data-comment-label');
      if (lbl) {
        var parts = lbl.split('|');
        var tagName = parts.slice(1).join('|');
        btn.classList.toggle('active', row.label === tagName);
      }
    });
  }

  function updateCommentReason(id) {
    var row = commentState.rows.find(function (r) { return r.id === id; });
    if (!row) return;
    var el = document.querySelector('[data-comment-reason="' + id + '"]');
    if (el) row.reason = el.value.trim();
  }

  function selectCommentLabel(id, label) {
    updateCommentReason(id);
    var row = commentState.rows.find(function (r) { return r.id === id; });
    if (!row) return;
    row.label = row.label === label ? '' : label;
    updateCommentStats();
    refreshCommentCardDOM(id);
  }

  function clearCommentRow(id) {
    var row = commentState.rows.find(function (r) { return r.id === id; });
    if (!row) return;
    row.label = '';
    row.reason = '';
    updateCommentStats();
    var card = document.querySelector('[data-comment-id="' + id + '"]');
    if (card) {
      var textarea = card.querySelector('.comment-reason-textarea');
      if (textarea) textarea.value = '';
    }
    refreshCommentCardDOM(id);
  }

  function jumpToNextCommentUnlabeled() {
    if (!commentState.rows.length) return;
    var unlabeled = commentState.rows.filter(function (r) { return !r.label; });
    if (!unlabeled.length) return;

    var filtered = getCommentFilteredRows();
    var visibleIds = {};
    filtered.forEach(function (r) { visibleIds[r.id] = true; });
    var candidates = unlabeled.filter(function (r) { return visibleIds[r.id]; });

    if (!candidates.length) {
      document.getElementById('commentStatusFilter').value = 'all';
      document.getElementById('commentTagFilter').value = 'all';
      document.getElementById('commentSearchInput').value = '';
      filtered = getCommentFilteredRows();
      candidates = commentState.rows.filter(function (r) { return !r.label; });
    }

    if (commentState.nextUnlabeledCursor >= candidates.length) commentState.nextUnlabeledCursor = 0;
    var target = candidates[commentState.nextUnlabeledCursor];
    commentState.nextUnlabeledCursor++;

    var idx = filtered.findIndex(function (r) { return r.id === target.id; });
    if (idx >= 0) commentState.currentPage = Math.floor(idx / commentState.pageSize) + 1;
    renderCommentCards();

    requestAnimationFrame(function () {
      var card = document.querySelector('[data-comment-id="' + target.id + '"]');
      if (!card) return;
      document.querySelectorAll('.comment-card-item.focused').forEach(function (el) { el.classList.remove('focused'); });
      card.classList.add('focused');
      card.scrollIntoView({ behavior: 'smooth', block: 'center' });
      setTimeout(function () { card.classList.remove('focused'); }, 1800);
    });
  }

  function exportCommentResult() {
    if (!commentState.rows.length) { alert('暂无可导出的数据'); return; }
    if (!window.XLSX) { alert('XLSX 库未加载'); return; }
    var data = commentState.rows.map(function (row) {
      var obj = { '标题': row.title, '评论': row.comment };
      Object.keys(row.aux).forEach(function (k) { obj[k] = row.aux[k]; });
      obj['标签'] = row.label;
      obj['理由'] = row.reason;
      return obj;
    });
    var ws = XLSX.utils.json_to_sheet(data);
    ws['!cols'] = Object.keys(data[0]).map(function (k) { return { wch: Math.max(12, Math.min(42, k.length + 12)) }; });
    var wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, '标注结果');
    XLSX.writeFile(wb, '评论标注结果.xlsx');
  }

  function clearCommentAll() {
    if (!commentState.rows.length) return;
    if (!confirm('确认清空当前上传数据和标注结果吗？')) return;
    commentState.rows = [];
    commentState.auxHeaders = [];
    commentState.nextUnlabeledCursor = 0;
    commentState.currentPage = 1;
    document.getElementById('commentFileInput').value = '';
    document.getElementById('commentFileName').textContent = '尚未上传文件';
    document.getElementById('commentSearchInput').value = '';
    document.getElementById('commentStatusFilter').value = 'all';
    document.getElementById('commentTagFilter').value = 'all';
    renderCommentCards();
  }

  function initCommentLabeling() {
    loadCommentTags();
    renderCommentTags();
    renderCommentCards();
  }

  // ── Init ───────────────────────────────────────────────────────
  function initApp() {
    loadRules();
    loadHistory();
    loadModelConfigs();
    loadPromptTemplates();
    loadBatchTasks();
    loadSampleLibrary();
    loadSampleTags();
    loadSampleDatasets();
    loadSampleKnowledge();
    loadLabelRules();
    loadLabelCases();
    loadLabelVersions();
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

    // Init default sample tags if empty
    if (!sampleTags.length) {
      sampleTags = DEFAULT_SAMPLE_TAGS.map(function (t) { return Object.assign({}, t); });
      saveSampleTags();
    }

    // Init demo samples if library is empty
    if (!sampleLibrary.length) {
      initDemoSamples();
    }
  }

  // ── Bootstrap ──────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', initApp);
})();
