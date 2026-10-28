# File: scripts/build_balanced_url_dataset.py
"""
Xây dựng tập dữ liệu URL chuẩn công nghiệp chống học vẹt (Anti-Shortcut Learning):
- Đa dạng hóa hình thức cho Benign: bao gồm URL dài (documentation, article slugs),
  tên miền có dấu gạch nối (Mercedes-Benz, Coca-Cola...), TLD hiện đại (.io, .dev, .ai, .app...),
  URL có query parameters (?utm_source=...), và đường dẫn sâu nhiều cấp (GitHub, docs).
- Đa dạng hóa Phishing: không chỉ bó hẹp ở TLD lạ hay dấu gạch nối, mà mở rộng sang .com/.net/.org,
  typosquatting không dấu gạch nối (vletcombank, techcombnak), IP address, subdomain deception,
  lừa đảo quốc tế (PayPal, Apple, Netflix) và link rút gọn.
- Bảo đảm cân bằng tỷ lệ và đa dạng tên miền.
"""
import csv
import os
import sys

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

ORIGINAL_DATA_PATH = 'data/url_phishing_dataset.csv'
TARGET_DATA_PATH = 'data/url_dataset_industrial.csv'

# 1. Danh sách Top Global Domains & Services
GLOBAL_BENIGN_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com", "instagram.com",
    "wikipedia.org", "yahoo.com", "whatsapp.com", "amazon.com", "reddit.com", "netflix.com",
    "linkedin.com", "microsoft.com", "bing.com", "live.com", "office.com", "github.com",
    "gitlab.com", "apple.com", "pinterest.com", "wordpress.org", "tumblr.com", "imgur.com",
    "stackoverflow.com", "cloudflare.com", "zoom.us", "spotify.com", "adobe.com", "dropbox.com",
    "twitch.tv", "medium.com", "quora.com", "imdb.com", "cnn.com", "bbc.com", "nytimes.com",
    "theguardian.com", "reuters.com", "bloomberg.com", "forbes.com", "nih.gov", "cdc.gov",
    "who.int", "un.org", "harvard.edu", "stanford.edu", "mit.edu", "berkeley.edu", "ox.ac.uk",
    "cam.ac.uk", "python.org", "pypi.org", "npmjs.com", "mozilla.org", "w3.org", "ietf.org",
    "apache.org", "kernel.org", "debian.org", "ubuntu.com", "centos.org", "docker.com",
    "kubernetes.io", "openai.com", "anthropic.com", "claude.ai", "chatgpt.com", "huggingface.co",
    "salesforce.com", "oracle.com", "ibm.com", "intel.com", "cisco.com", "dell.com", "hp.com",
    "raw.githubusercontent.com", "gist.githubusercontent.com", "developer.mozilla.org",
    "docs.python.org", "docs.docker.com", "cloud.google.com", "aws.amazon.com"
]

# 2. Tên miền Benign có TLD công nghệ hiện đại (.io, .dev, .ai, .app, .co, .org, .de)
MODERN_TECH_BENIGN_DOMAINS = [
    "flutter.dev", "web.dev", "go.dev", "android.dev", "react.dev", "vuejs.org",
    "spring.io", "redis.io", "socket.io", "github.io", "gitlab.io", "ssp-platform.io",
    "prisma.io", "nextjs.org", "astro.build", "deno.land", "bun.sh", "supabase.com",
    "vercel.app", "netlify.app", "linear.app", "notion.so", "raycast.app",
    "stability.ai", "jasper.ai", "runwayml.com", "perplexity.ai", "elevenlabs.io",
    "spiegel.de", "zeit.de", "bild.de", "heise.de", "golem.de"
]

# 3. Tên miền Benign hợp pháp CÓ DẤU GẠCH NỐI (Chống học vẹt quy tắc dấu gạch nối)
HYPHEN_BENIGN_DOMAINS = [
    "mercedes-benz.com", "coca-cola.com", "t-mobile.com", "best-buy.com", "wal-mart.com",
    "rolls-royce.com", "harley-davidson.com", "lockheed-martin.com", "hewlett-packard.com",
    "e-banking.vietcombank.com.vn", "ba-ria-vung-tau.gov.vn", "khanh-hoa.gov.vn",
    "bac-lieu.gov.vn", "thua-thien-hue.gov.vn", "dong-nai.gov.vn", "binh-duong.gov.vn",
    "tech-blog.ssp-platform.io", "flutter-community.dev", "e-commerce.vn",
    "mercedes-benz-trucks.com", "rolls-royce-motorcars.com", "best-buy-deals.shopping.net",
    "engineering-blog.tech-company.io", "cloud-platform.enterprise-services.dev",
    "tp-ho-chi-minh.gov.vn", "tinh-thua-thien-hue.gov.vn"
]

# 4. Danh sách Top Vietnamese Domains
VN_BENIGN_DOMAINS = [
    # Ngân hàng & Tài chính
    "vietcombank.com.vn", "techcombank.com.vn", "mbbank.com.vn", "bidv.com.vn", "agribank.com.vn",
    "vpbank.com.vn", "acb.com.vn", "tpbank.com.vn", "sacombank.com.vn", "vib.com.vn",
    "vietinbank.vn", "hdbank.com.vn", "shb.com.vn", "msb.com.vn", "ocb.com.vn", "seabank.com.vn",
    "lpbank.com.vn", "eximbank.com.vn", "pvcombank.com.vn", "bacabank.vn", "namabank.com.vn",
    "momo.vn", "zalopay.vn", "zalo.me", "vnpay.vn", "shopeepay.vn", "payoo.vn",
    # Viễn thông
    "viettel.vn", "vietteltelecom.vn", "viettelmoney.vn", "viettelpost.vn", "myviettel.vn",
    "mobifone.vn", "mobifone.com.vn", "vinaphone.vn", "vinaphone.com.vn", "vnpt.vn", "vietnamobile.com.vn", "fpt.vn",
    # Chính phủ & Dịch vụ công
    "chinhphu.vn", "baochinhphu.vn", "dichvucong.gov.vn", "vneid.gov.vn", "bocongan.gov.vn",
    "baohiemxahoi.gov.vn", "gdt.gov.vn", "thuedientu.gdt.gov.vn", "tinnhiemmang.vn", "ncsc.gov.vn", "chongluadao.vn",
    # Thương mại điện tử & Bán lẻ
    "shopee.vn", "lazada.vn", "tiki.vn", "sendo.vn", "thegioididong.com", "dienmayxanh.com",
    "bachhoaxanh.com", "fptshop.com.vn", "cellphones.com.vn", "hoanghamobile.com", "mediamart.vn",
    # Báo chí & Truyền hình
    "vnexpress.net", "dantri.com.vn", "tuoitre.vn", "thanhnien.vn", "vietnamnet.vn", "vtv.vn",
    "laodong.vn", "tienphong.vn", "soha.vn", "kenh14.vn", "znews.vn", "plo.vn", "cafef.vn", "cafebiz.vn",
    # Trường đại học & Nghiên cứu
    "vnu.edu.vn", "hust.edu.vn", "neu.edu.vn", "ftu.edu.vn", "uit.edu.vn", "hcmut.edu.vn", "ueh.edu.vn"
]

# Các mẫu đường dẫn Benign: ngắn, trung bình, dài (article slug, docs, deep nested repo paths)
BENIGN_PATHS_SHORT = [
    "", "/", "/about", "/contact", "/pricing", "/faq", "/support", "/help", "/privacy", "/terms"
]

BENIGN_PATHS_DOCS_AND_SLUGS = [
    # Documentation & Dev paths (rất dài, nhiều cấp gạch chéo, nhiều gạch nối)
    "/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/reduce",
    "/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    "/docs/v2/getting-started/installation-and-configuration-guide",
    "/engineering-culture-at-modern-tech-startup",
    "/questions/1234567/how-to-fix-memory-leak-in-node-js-application",
    "/questions/7654321/optimizing-postgresql-query-performance-with-indexing",
    "/torvalds/linux/blob/master/include/linux/types.h",
    "/facebook/react/blob/main/packages/react/src/ReactElement.js",
    "/tensorflow/tensorflow/tree/master/tensorflow/python/framework",
    # Deep nested repository paths (7-9 slashes, kebab-case components)
    "/user/proj/master/src/components/user-profile-widget.tsx",
    "/org/repo/blob/release-v2.0/packages/core/src/utils/string-helpers.ts",
    "/developer/mobile-app/tree/feature-branch/android/app/src/main/res/values/styles.xml",
    "/enterprise/system/blob/main/backend/services/payment-gateway/src/main.py",
    # Article & News slugs (dài, có ngày tháng, có gạch nối)
    "/news/2026/04/15/viet-nam-thuc-day-chuyen-doi-so-quoc-gia-va-phat-trien-kinh-te.html",
    "/kinh-doanh/ngan-hang-nha-nuoc-dieu-chinh-lai-suat-dieu-hanh-on-dinh-vi-mo-12345.html",
    "/giao-duc/cac-truong-dai-hoc-cong-bo-phuong-an-tuyen-sinh-nam-2026-67890.html",
    "/technology/how-to-build-scalable-microservices-with-kubernetes-and-docker",
    "/lifestyle/tips-for-healthy-work-life-balance-in-remote-working-era",
    "/product/laptop-asus-zenbook-oled-14-inch-core-ultra-7-155h-32gb-1tb",
    "/item/dien-thoai-apple-iphone-16-pro-max-256gb-chinh-hang-vna-45678.html",
    "/clearance-electronics",
    "/blogs/aws/new-amazon-ec2-c7g-instances-graviton3-processors",
    "/t/how-to-set-up-zero-trust-access-policies/482910"
]

BENIGN_PATHS_WITH_QUERY = [
    "/search?q=machine+learning+tutorial+for+beginners&lang=vi",
    "/products?category=electronics&brand=asus&sort=price_asc&page=2",
    "/articles?tag=artificial-intelligence&page=1&limit=20",
    "/search?query=huong+dan+khai+thue+dien+tu+truc+tuyen",
    "/feed?utm_source=google&utm_medium=cpc&utm_campaign=summer_promo_2026",
    "/view?tab=reviews&rating=5&sort=newest&filter=verified_purchase"
]

# 5. Mẫu Phishing đối kháng đa dạng (Chống học vẹt)
PHISHING_PATTERNS = [
    # Combosquatting trên các TLD phổ biến (.com, .net, .org - không chỉ TLD lạ)
    "http://vietcombank-login-online.com/auth",
    "https://vietcombank-smart-otp.net/verify",
    "http://techcombank-xacthuc.org/login",
    "https://techcombank-ebanking.com/portal",
    "http://mbbank-nhanthuong.net/claim",
    "https://mb-smartotp-update.org/step1",
    "http://bidv-baomat-taikhoan.com/secure",
    "https://agribank-vaytien-online.net/dangky",
    "http://acb-khuyenmai-trian.com/gift",
    "https://vpbank-neo-secure.org/auth",
    "http://tpbank-ebank-login.com/signin",
    "https://sacombank-pay-verify.net/portal",
    "http://vib-chamsockhachhang.com/support",
    "https://vietinbank-smart-portal.org/login",
    # Phishing KHÔNG DÙNG GẠCH NỐI (Typosquatting & Direct Concatenation)
    "http://vietcombanklogin.com/webscr",
    "http://vietcombankebank.net/login",
    "http://techcombankonline.com/auth",
    "http://mbbankonline.org/login",
    "http://bidvsmartotp.com/verify",
    "http://shopeevntrian.com/nhanthuong",
    "http://zalopaykhuyenmai.com/vongquay",
    "http://viettelposttraohang.com/tracking",
    # Typosquatting đánh tráo ký tự
    "http://vletcombank.com/login",
    "http://techcombnak.com/auth",
    "http://mbbannk.com/smartotp",
    "http://agrlbank.com/ebank",
    "http://paypa1-security.com/signin",
    "http://faceb00k-login.com/checkpoint",
    "http://netfllx-billing.com/update",
    # Subdomain Deception
    "http://vietcombank.com.vn.ebank-auth-update.info/login.php",
    "https://mbbank.com.vn.nhan-qua-2026.xyz/portal/claim",
    "http://techcombank.com.vn.kichhoat-smartotp.top/auth",
    "http://vneid.gov.vn.dichvucong-capnhat.site/vneid-install.apk",
    "https://bocongan.gov.vn.lenh-bat-giam-truy-to.xyz/ho-so-vu-an",
    "http://shopee.vn.voucher-trian-100k.top/nhan-thuong",
    "http://viettel.vn.napthe-khuyenmai50.xyz/nap-tien",
    "http://dichvucong.gov.vn.hoanthue-thu-nhap.site/portal",
    "http://apple.com.id-support-verify.net/auth",
    # IP Address trực tiếp
    "http://172.67.145.22/vcb/login.php",
    "http://103.45.23.11:8080/portal/auth",
    "http://192.241.155.3/smartotp/index.html",
    "http://45.76.12.98/bidv/verify",
    "http://192.168.1.100/admin/login.php",
    "http://14.225.16.180/mbbank/auth",
    # Cờ bạc, cá cược, lừa đảo việc làm
    "https://tai-xiu-go88-doi-thuong.club",
    "http://sunwin-songbac-online.vip",
    "http://kubet-casino-dangky.top",
    "https://viec-nhe-luong-cao-ctv.xyz/dang-ky",
    "http://chot-don-shopee-kiem-tien.top/task",
    "https://nhan-code-no-hu-100k.site",
    "http://gamebai-doithuong-sieutoc.cc",
    # Phishing quốc tế nổi tiếng
    "http://paypal-verification-account-security.com/webscr",
    "http://apple-id-manage-security.com/auth",
    "http://wellsfargo-update-client.com/login",
    "http://secure-banking-portal-verification.org/signin",
    "http://chase-bank-verify-profile.com/auth",
    "http://binance-security-authentication.net/login",
    "http://steamcommunity-gift-trade.org/trade",
    # Link rút gọn lừa đảo
    "http://tinyurl.com/vcb-smartotp-update",
    "http://bit.ly/mbbank-nhan-qua-2026",
    "http://is.gd/tpbank-xacthuc"
]


def generate_industrial_dataset():
    urls = []
    seen = set()

    # 1. Nạp từ tập gốc nếu có
    if os.path.exists(ORIGINAL_DATA_PATH):
        with open(ORIGINAL_DATA_PATH, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                u = row.get('URL', '').strip()
                t = row.get('type', '').strip().lower()
                if u and u not in seen:
                    seen.add(u)
                    urls.append((u, t))

    initial_benign = sum(1 for _, t in urls if t == 'benign')
    initial_phishing = sum(1 for _, t in urls if t == 'phishing')
    print(f"Mẫu từ tập gốc: {len(urls)} (Benign: {initial_benign}, Phishing: {initial_phishing})")

    # 2. Sinh Benign URLs đa dạng, chống học vẹt (Anti-Shortcut Benign Generation)
    all_benign_domains = (
        GLOBAL_BENIGN_DOMAINS
        + MODERN_TECH_BENIGN_DOMAINS
        + HYPHEN_BENIGN_DOMAINS
        + VN_BENIGN_DOMAINS
    )

    added_benign = 0
    for d in all_benign_domains:
        # Đường dẫn ngắn
        for p in BENIGN_PATHS_SHORT:
            for proto in ["https://", "http://"]:
                full_url = f"{proto}{d}{p}"
                if full_url not in seen:
                    seen.add(full_url)
                    urls.append((full_url, 'benign'))
                    added_benign += 1

        # Đường dẫn dài (Tài liệu, bài báo, slug gạch nối, deep repo paths) - HARD NEGATIVES
        for p in BENIGN_PATHS_DOCS_AND_SLUGS:
            full_url = f"https://{d}{p}"
            if full_url not in seen:
                seen.add(full_url)
                urls.append((full_url, 'benign'))
                added_benign += 1

        # Đường dẫn kèm Query Parameters
        for p in BENIGN_PATHS_WITH_QUERY:
            full_url = f"https://{d}{p}"
            if full_url not in seen:
                seen.add(full_url)
                urls.append((full_url, 'benign'))
                added_benign += 1

    print(f"Đã bổ sung mẫu Benign đa dạng (Docs/Slugs/Tech/Hyphens/Deep paths): {added_benign} mẫu")

    # 3. Sinh Phishing URLs đa dạng
    added_phishing = 0
    # Mẫu từ template cơ sở với nhiều biến thể endpoint
    for template in PHISHING_PATTERNS:
        for extra in ["", "/login", "/verify", "/update", "/step1", "/confirm.php", "?user=client", "?ref=sms"]:
            phish_url = f"{template}{extra}"
            if phish_url not in seen:
                seen.add(phish_url)
                urls.append((phish_url, 'phishing'))
                added_phishing += 1

    # Phishing ngân hàng trên các TLD khác nhau: bao gồm cả .com, .net, .org VÀ các TLD nguy cơ cao
    all_tlds = [
        # TLD thông thường (kẻ lừa đảo mua domain .com/.net giả mạo)
        "com", "net", "org", "co", "info",
        # TLD nguy cơ cao
        "xyz", "top", "club", "site", "online", "cc", "vip", "cfd", "sbs", "buzz", "monster", "icu"
    ]
    banks = [
        "vietcombank", "techcombank", "mbbank", "bidv", "acb", "tpbank", "vpbank",
        "agribank", "sacombank", "vib", "vietinbank", "shopee", "zalopay", "vneid", "bocongan"
    ]
    actions = [
        "login", "dangnhap", "smartotp", "ebanking", "xacthuc", "baomat", "capnhat",
        "nhanthuong", "trian", "vaytien", "caiapp"
    ]

    for bank in banks:
        for action in actions:
            for tld in all_tlds:
                # Biến thể có gạch nối
                p_url_hyphen = f"http://{bank}-{action}.{tld}/login"
                if p_url_hyphen not in seen:
                    seen.add(p_url_hyphen)
                    urls.append((p_url_hyphen, 'phishing'))
                    added_phishing += 1

                # Biến thể KHÔNG có gạch nối (Chống học vẹt)
                p_url_nohyphen = f"http://{bank}{action}.{tld}/auth"
                if p_url_nohyphen not in seen:
                    seen.add(p_url_nohyphen)
                    urls.append((p_url_nohyphen, 'phishing'))
                    added_phishing += 1

    print(f"Đã bổ sung mẫu Phishing đối kháng đa dạng: {added_phishing} mẫu")

    total = len(urls)
    total_benign = sum(1 for _, t in urls if t == 'benign')
    total_phishing = sum(1 for _, t in urls if t == 'phishing')
    print("=" * 65)
    print(f"Tổng số mẫu tập dữ liệu mới: {total} (Benign: {total_benign}, Phishing: {total_phishing})")

    with open(TARGET_DATA_PATH, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["url", "type"])
        for u, t in urls:
            writer.writerow([u, t])

    print(f"Đã lưu tập dữ liệu URL chuẩn công nghiệp tại: {TARGET_DATA_PATH}")
    print("=" * 65)


if __name__ == '__main__':
    generate_industrial_dataset()
