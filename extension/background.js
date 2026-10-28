// File: extension/background.js
// He thong Giam dinh An ninh & Tien ich P-Sieve (Manifest V3)
// Ho tro Service Worker khong lo loi Mixed Content hoac chan mang cuc bo

const API_CANDIDATE_BASES = [
  "https://p-sieve.onrender.com/api/v1",
  "http://127.0.0.1:8001/api/v1",
  "http://127.0.0.1:8000/api/v1"
];

// Danh ba ten mien tin cay quoc gia va to chuc lon Viet Nam
const TRUSTED_DOMAINS = [
  "gov.vn", "edu.vn", "tinnhiemmang.vn", "chongluadao.vn", "ncsc.gov.vn",
  "dichvucong.gov.vn", "vneid.gov.vn", "chinhphu.vn", "baochinhphu.vn",
  "vnexpress.net", "dantri.com.vn", "tuoitre.vn", "thanhnien.vn", "vietnamnet.vn",
  "vtv.vn", "tienphong.vn", "laodong.vn", "soha.vn", "kenh14.vn", "znews.vn",
  "google.com", "google.com.vn", "youtube.com", "facebook.com", "fb.com",
  "messenger.com", "zalo.me", "github.com", "stackoverflow.com", "wikipedia.org",
  "vietcombank.com.vn", "techcombank.com.vn", "mbbank.com.vn", "bidv.com.vn",
  "agribank.com.vn", "vpbank.com.vn", "acb.com.vn", "tpbank.com.vn",
  "sacombank.com.vn", "vib.com.vn", "vietinbank.vn", "hdbank.com.vn", "shb.com.vn",
  "shopee.vn", "lazada.vn", "tiki.vn", "sendo.vn", "thegioididong.com",
  "dienmayxanh.com", "fptshop.com.vn", "viettel.vn", "vinaphone.vn", "mobifone.vn",
  "vnptmoney.vn", "tv360.vn", "viettelstore.vn", "homecredit.vn", "vtmoney.vn",
  "p-sieve.onrender.com", "scam-sieve.onrender.com", "psieve.onrender.com", "localhost", "127.0.0.1"
];

// Danh ba tinh bao ten mien doc hai / bi chiem quyen dieu khien
const KNOWN_MALICIOUS_DOMAINS = [
  "musictoyourhome.com",
  "www.musictoyourhome.com",
  "pruisturin.com",
  "shoptrendr.top",
  "evn-cskh.vn",
  "vcb-digibank-login.xyz",
  "vietcornbank-ebank.xyz",
  "quatang-triandacbiet.xyz",
  "vieclam-tainha.site",
  "1wyjiv.life"
];

// Bo nho dem ket qua giam dinh URL nham toi uu toc do (< 0.1ms)
const URL_VERDICT_CACHE = new Map();

// Ham thuc thi truy van an toan qua cac cong backend
async function fetchApi(endpoint, body = null, method = "GET") {
  let lastError = null;
  for (const base of API_CANDIDATE_BASES) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);
      const options = {
        method,
        headers: { "Content-Type": "application/json" },
        signal: controller.signal
      };
      if (body) {
        options.body = JSON.stringify(body);
      }
      const resp = await fetch(`${base}${endpoint}`, options);
      clearTimeout(timeoutId);
      if (resp.ok) {
        return await resp.json();
      }
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError || new Error("Khong the ket noi den may chu P-Sieve");
}

// 1. Khoi tao Menu chuot phai (Context Menu)
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "psieve-check-selection",
    title: "Kiem tra van ban da chon voi P-Sieve",
    contexts: ["selection"]
  });

  chrome.contextMenus.create({
    id: "psieve-check-link",
    title: "Kiem tra lien ket nay voi P-Sieve",
    contexts: ["link"]
  });
});

// 2. Xu ly su kien click Menu chuot phai
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  let targetContent = "";
  if (info.menuItemId === "psieve-check-selection" && info.selectionText) {
    targetContent = info.selectionText.trim();
  } else if (info.menuItemId === "psieve-check-link" && info.linkUrl) {
    targetContent = info.linkUrl.trim();
  }

  if (!targetContent) return;

  try {
    const data = await fetchApi("/scan", { content: targetContent, input_type: "auto" }, "POST");
    let notifTitle = "P-Sieve: Noi Dung An Toan";
    if (data.risk_level === "HIGH") {
      notifTitle = "P-Sieve: CANH BAO NGUY CO LUA DAO";
    } else if (data.risk_level === "MEDIUM") {
      notifTitle = "P-Sieve: CAN THAN TRONG";
    }

    const notifMessage = `Diem rui ro: ${data.score}/100\n${data.status_label}\n${data.recommendation}`;
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: notifTitle,
      message: notifMessage,
      priority: 2
    });
  } catch (err) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "P-Sieve: Loi ket noi",
      message: "Khong the ket noi den may chu P-Sieve (cong 8001/8000). Vui long kiem tra backend.",
      priority: 1
    });
  }
});

// 3. Ham cap nhat Huy hieu tren thanh cong cu (Extension Badge)
// Ho tro day du bo 3 chuan an ninh quoc te: SAFE (Xanh) | WARN (Cam) | DANGER (Do)
async function updateTabBadge(tabId, url) {
  if (!url || url.startsWith("chrome://") || url.startsWith("edge://") || url.startsWith("about:")) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();

    // 1. Kiem tra danh ba to chuc tin cay (0ms)
    const isGovEdu = host.endsWith(".gov.vn") || host.endsWith(".edu.vn");
    if (isGovEdu || TRUSTED_DOMAINS.some(d => host === d || host.endsWith("." + d))) {
      chrome.action.setBadgeText({ tabId, text: "SAFE" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#16a34a" });
      URL_VERDICT_CACHE.set(url, { score: 0, is_scam: false, verdict: "SAFE" });
      return;
    }

    // 2. Kiem tra nhanh cac duoi ten mien nguy co cao hoac tu khoa lua dao nguy hiem (DANGER)
    const dangerousTlds = [
      "life", "xyz", "top", "vip", "work", "click", "buzz", "club", "cam",
      "fit", "rest", "icu", "sbs", "cfd", "space", "link", "monster", "tk", "ml", "ga",
      "bid", "bond", "cyou", "download", "stream"
    ];
    const dangerousKeywords = ["1win", "sunwin", "go88", "taixiu", "hitclub", "b52", "rikvip", "smartotp", "nhanqua", "quaythuong"];
    const tld = host.split(".").pop();
    const isKnownMalicious = KNOWN_MALICIOUS_DOMAINS.some(d => host === d || host.endsWith("." + d));

    if (isKnownMalicious || dangerousTlds.includes(tld) || dangerousKeywords.some(kw => host.includes(kw))) {
      chrome.action.setBadgeText({ tabId, text: "DANGER" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#aa0a27" });
      URL_VERDICT_CACHE.set(url, { score: 100, is_scam: true, verdict: "DANGEROUS" });
      return;
    }

    // 2b. Kiem tra nhanh dau hieu kha nghi cuc bo (WARN: bet, cacuoc, keonhacai, casino...)
    const suspiciousKeywords = ["bet", "cacuoc", "keonhacai", "soikeo", "bong88", "w88", "fun88", "m88", "fb88", "bk8", "dafabet", "casino", "gamebai"];
    if (tld === "bet" || suspiciousKeywords.some(kw => host.includes(kw))) {
      chrome.action.setBadgeText({ tabId, text: "WARN" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#d97706" });
      URL_VERDICT_CACHE.set(url, { score: 45, is_scam: false, verdict: "SUSPICIOUS" });
    }

    // 3. Kiem tra bo nho dem (0.01ms)
    if (URL_VERDICT_CACHE.has(url)) {
      const cached = URL_VERDICT_CACHE.get(url);
      applyBadge(tabId, cached.score, cached.is_scam, cached.verdict);
      return;
    }

    // 4. Kiem tra qua backend API P-Sieve
    const res = await fetchApi("/inspect-heuristics", { url, dom: {} }, "POST");
    const isScam = res.verdict === "DANGEROUS" || (res.safety_score !== undefined && res.safety_score < 50);
    const isSusp = res.verdict === "SUSPICIOUS" || (res.safety_score !== undefined && res.safety_score >= 50 && res.safety_score < 80);
    const score = Math.max(0, 100 - (res.safety_score ?? 100));
    const v = isScam ? "DANGEROUS" : (isSusp ? "SUSPICIOUS" : (res.is_trusted ? "SAFE" : "UNKNOWN"));
    URL_VERDICT_CACHE.set(url, { score, is_scam: isScam, verdict: v });
    applyBadge(tabId, score, isScam, v);
  } catch (e) {
    // Neu trang web da duoc phat hien co dau hieu kha nghi hay doc hai tu cuc bo thi giu nguyen
    if (!URL_VERDICT_CACHE.has(url)) {
      chrome.action.setBadgeText({ tabId, text: "" });
    }
  }
}

function applyBadge(tabId, score, isScam, verdict = null) {
  if (isScam || verdict === "DANGEROUS" || score >= 60) {
    chrome.action.setBadgeText({ tabId, text: "DANGER" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#aa0a27" });
  } else if (verdict === "SUSPICIOUS" || verdict === "WARN" || (score >= 20 && score < 60)) {
    chrome.action.setBadgeText({ tabId, text: "WARN" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#d97706" });
  } else if (verdict === "SAFE") {
    chrome.action.setBadgeText({ tabId, text: "SAFE" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#16a34a" });
  } else {
    // Tuyet doi khong tu y hien thi SAFE tren thanh cong cu cho cac web la chua kiem chung!
    chrome.action.setBadgeText({ tabId, text: "" });
  }
}

// 4. Lang nghe thay doi URL tren tab
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    updateTabBadge(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url) {
      updateTabBadge(activeInfo.tabId, tab.url);
    }
  } catch (e) {}
});

// 5. Cung cap Proxy API qua Message Passing cho Content Script (Tranh Mixed Content)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "leave_dangerous_site") {
    const tabId = sender && sender.tab ? sender.tab.id : null;
    if (tabId) {
      chrome.tabs.update(tabId, { url: "https://www.google.com" }, () => {
        if (chrome.runtime.lastError) {
          chrome.tabs.remove(tabId);
        }
      });
    }
    sendResponse({ success: true });
    return true;
  }

  if (request.action === "close_tab") {
    const tabId = sender && sender.tab ? sender.tab.id : null;
    if (tabId) {
      chrome.tabs.remove(tabId);
    }
    sendResponse({ success: true });
    return true;
  }

  if (request.action === "update_badge") {
    const tabId = (sender && sender.tab && sender.tab.id) || request.tabId;
    if (tabId) {
      applyBadge(tabId, request.score || 0, request.is_scam || false, request.verdict);
    }
    sendResponse({ success: true });
    return true;
  }

  if (request.action === "inspect_page") {
    fetchApi("/inspect-page", request.payload, "POST")
      .then((data) => {
        if (sender && sender.tab && sender.tab.id && request.payload && request.payload.url) {
          const isScam = data.is_scam || (data.score >= 60);
          const isSusp = !isScam && (data.score >= 20 || data.risk_level === "MEDIUM");
          const v = isScam ? "DANGEROUS" : (isSusp ? "SUSPICIOUS" : "SAFE");
          URL_VERDICT_CACHE.set(request.payload.url, { score: data.score, is_scam: isScam, verdict: v });
          applyBadge(sender.tab.id, data.score, isScam, v);
        }
        sendResponse({ success: true, data });
      })
      .catch((err) => {
        sendResponse({ success: false, error: err.message });
      });
    return true; // Cho phep phan hoi bat dong bo
  }

  if (request.action === "inspect_heuristics") {
    fetchApi("/inspect-heuristics", request.payload, "POST")
      .then((data) => sendResponse({ success: true, data }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (request.action === "scan_content") {
    fetchApi("/scan", request.payload, "POST")
      .then((data) => sendResponse({ success: true, data }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }
});
