import os
import time
import random
import glob
import json
import zipfile
import requests
import re
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import TimeoutException, ElementClickInterceptedException


# --- Constants ---
MODAL_BACKDROP_SELECTOR   = (By.CLASS_NAME, "modal-two-backdrop")
CONFIRM_BUTTON_SELECTOR   = (By.CSS_SELECTOR, ".button-solid-norm:nth-child(2)")
EXTEND_BTN_SELECTOR       = "button.button-outline-weak"
DOWNLOAD_DIR              = os.path.join(os.getcwd(), "downloaded_configs")
SERVER_ID_LOG_FILE        = os.path.join(os.getcwd(), "downloaded_wg_ids.json")
MAX_DOWNLOADS_PER_SESSION = 20
RELOGIN_DELAY             = 120

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID")

if not os.path.exists(DOWNLOAD_DIR):
    os.makedirs(DOWNLOAD_DIR)


# ---------------------------------------------------------------------------
# x-ui 转换工具函数
# ---------------------------------------------------------------------------

def _build_xui_entry(tag, private_key, address, public_key, allowed_ips, endpoint, keep_alive):
    return {
        "protocol": "wireguard",
        "tag": tag,
        "settings": {
            "secretKey":   private_key,
            "address":     address,
            "mtu":         1420,
            "workers":     2,
            "noKernelTun": False,
            "peers": [{
                "publicKey":  public_key,
                "allowedIPs": allowed_ips,
                "endpoint":   endpoint,
                "keepAlive":  keep_alive,
            }],
        },
    }


def parse_conf_to_xui(conf_path):
    """
    将一个 ProtonVPN WireGuard .conf 解析为 x-ui outbound 对象列表。
    双栈 → 生成 -ipv4 和 -ipv6 两条；单栈 → 一条。
    """
    try:
        with open(conf_path, "r", encoding="utf-8") as f:
            content = f.read()

        section  = None
        data     = {"interface": {}, "peer": {}}
        base_tag = os.path.basename(conf_path).rsplit(".", 1)[0]
        ipv6_endpoint_commented = None

        for raw_line in content.splitlines():
            line = raw_line.strip()

            if section == "peer":
                if line.startswith("#") and not line.lower().startswith("# endpoint"):
                    candidate = line.lstrip("# ").strip()
                    if re.match(r"^[A-Z]{2}[-A-Z0-9]*#\d+$", candidate):
                        base_tag = candidate
                    continue
                m = re.match(r"^#\s*endpoint\s*=\s*(\[.+?\]:\d+)$", line, re.IGNORECASE)
                if m:
                    ipv6_endpoint_commented = m.group(1)
                    continue

            if line.startswith("#") or not line:
                continue
            if line == "[Interface]": section = "interface"; continue
            if line == "[Peer]":      section = "peer";      continue

            if "=" in line:
                k, _, v = line.partition("=")
                if section:
                    data[section][k.strip().lower()] = v.strip()

        iface, peer = data["interface"], data["peer"]
        private_key = iface.get("privatekey", "")
        public_key  = peer.get("publickey", "")
        endpoint_v4 = peer.get("endpoint", "")

        if not all([private_key, public_key, endpoint_v4]):
            print(f"[xui] Skipping {conf_path} — missing required fields.")
            return []

        raw_addrs   = [a.strip() for a in iface.get("address", "").split(",") if a.strip()]
        ipv4_addrs  = [a for a in raw_addrs if "." in a]
        ipv6_addrs  = [a for a in raw_addrs if ":" in a]
        allowed_ips = [a.strip() for a in peer.get("allowedips", "0.0.0.0/0").split(",") if a.strip()]
        keep_alive  = int(peer.get("persistentkeepalive", 25))

        results       = []
        has_v4, has_v6 = bool(ipv4_addrs), bool(ipv6_addrs)

        if has_v4 and has_v6:
            results.append(_build_xui_entry(f"{base_tag}-ipv4", private_key, ipv4_addrs,
                                             public_key, allowed_ips, endpoint_v4, keep_alive))
            endpoint_v6 = ipv6_endpoint_commented or endpoint_v4
            results.append(_build_xui_entry(f"{base_tag}-ipv6", private_key, ipv6_addrs,
                                             public_key, allowed_ips, endpoint_v6, keep_alive))
        elif has_v4:
            results.append(_build_xui_entry(base_tag, private_key, ipv4_addrs,
                                             public_key, allowed_ips, endpoint_v4, keep_alive))
        elif has_v6:
            endpoint_v6 = ipv6_endpoint_commented or endpoint_v4
            results.append(_build_xui_entry(base_tag, private_key, ipv6_addrs,
                                             public_key, allowed_ips, endpoint_v6, keep_alive))
        else:
            print(f"[xui] Skipping {conf_path} — no valid Address found.")

        return results

    except Exception as e:
        print(f"[xui] Failed to parse {conf_path}: {e}")
        return []


def build_xui_into_zip(conf_dir, zipf):
    """遍历所有 .conf，转换后写入 ZIP 的 xui_outbounds/<CC>/<tag>.json。"""
    total = 0
    for filename in sorted(os.listdir(conf_dir)):
        if not filename.endswith(".conf"):
            continue
        name_no_ext = filename.rsplit(".", 1)[0]
        clean_name  = re.sub(r"\s*\(\d+\)$", "", name_no_ext).strip().lower()
        prefix      = clean_name.replace("wg-", "")
        code        = re.split(r"[-#]", prefix)[0].upper()
        country     = code if (len(code) == 2 and code.isalpha()) else "OTHER"

        entries = parse_conf_to_xui(os.path.join(conf_dir, filename))
        for entry in entries:
            tag       = entry["tag"]
            safe_name = tag.replace("#", "_") + ".json"
            arc_path  = f"xui_outbounds/{country}/{safe_name}"
            zipf.writestr(arc_path, json.dumps(entry, indent=2, ensure_ascii=False))
            total += 1

    print(f"[xui] {total} JSON files written to xui_outbounds/.")
    return total


# ---------------------------------------------------------------------------
# 工具：JS 安全点击
# 修复 "move target out of bounds" 和 headless 下 ActionChains 点击失效问题
# ---------------------------------------------------------------------------

def js_click(driver, element):
    """
    scrollIntoView 后用 JS .click()，完全绕开 ActionChains / move_to_element，
    不受 headless 窗口尺寸限制。
    """
    driver.execute_script(
        "arguments[0].scrollIntoView({block: 'center', inline: 'nearest'});", element
    )
    time.sleep(0.3)
    driver.execute_script("arguments[0].click();", element)


# ---------------------------------------------------------------------------
# 主类
# ---------------------------------------------------------------------------

class ProtonVPN:
    def __init__(self):
        self.options = webdriver.ChromeOptions()
        self.options.add_argument("--headless")
        self.options.add_argument("--no-sandbox")
        self.options.add_argument("--disable-dev-shm-usage")
        self.options.add_argument("--disable-gpu")
        self.options.add_argument("--window-size=1920,1080")

        prefs = {
            "download.default_directory": DOWNLOAD_DIR,
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True,
        }
        self.options.add_experimental_option("prefs", prefs)
        self.driver = None

    def setup(self):
        self.driver = webdriver.Chrome(options=self.options)
        self.driver.set_window_size(1936, 1048)
        self.driver.implicitly_wait(10)
        print("WebDriver initialized.")

    def teardown(self):
        if self.driver:
            self.driver.quit()
            print("WebDriver closed.")

    def load_downloaded_ids(self):
        if os.path.exists(SERVER_ID_LOG_FILE):
            try:
                with open(SERVER_ID_LOG_FILE, "r") as f:
                    return set(json.load(f))
            except json.JSONDecodeError:
                return set()
        return set()

    def save_downloaded_ids(self, ids):
        with open(SERVER_ID_LOG_FILE, "w") as f:
            json.dump(list(ids), f)

    # ── 登录 ──────────────────────────────────────────────────────────────────
    def login(self, username, password):
        try:
            self.driver.get("https://protonvpn.com/")
            time.sleep(1)
            self.driver.find_element(
                By.XPATH, "//a[contains(@href, 'https://account.protonvpn.com/login')]"
            ).click()
            time.sleep(1)
            self.driver.find_element(By.ID, "username").send_keys(username)
            time.sleep(1)
            self.driver.find_element(By.CSS_SELECTOR, ".button-large").click()
            time.sleep(1)
            self.driver.find_element(By.ID, "password").send_keys(password)
            time.sleep(1)
            self.driver.find_element(By.CSS_SELECTOR, ".button-large").click()
            time.sleep(3)
            print("Login Successful.")
            return True
        except Exception as e:
            print(f"Error Login: {e}")
            return False

    # ── 导航到 Downloads（多选择器容错）─────────────────────────────────────────
    def navigate_to_downloads(self):
        selectors = [
            (By.XPATH,        "//a[contains(@href,'/downloads')]"),
            (By.XPATH,        "//*[contains(@class,'navigation-item')][.//*[contains(text(),'Download')]]"),
            (By.CSS_SELECTOR, ".navigation-item:nth-child(7) .text-ellipsis"),
        ]
        for loc in selectors:
            try:
                WebDriverWait(self.driver, 8).until(EC.element_to_be_clickable(loc)).click()
                time.sleep(2)
                print("Navigated to Downloads page.")
                return True
            except Exception:
                continue
        print("Error Navigating to Downloads: all selectors failed.")
        return False

    # ── 登出 ──────────────────────────────────────────────────────────────────
    def logout(self):
        try:
            self.driver.get("https://account.protonvpn.com/logout")
            time.sleep(1)
            return True
        except Exception:
            try:
                self.driver.find_element(By.CSS_SELECTOR, ".p-1").click()
                time.sleep(1)
                self.driver.find_element(By.CSS_SELECTOR, ".mb-4 > .button").click()
                time.sleep(1)
                return True
            except Exception:
                return False

    # ── ★ 批量续期（修复版）──────────────────────────────────────────────────────
    #
    # 原问题：
    #   1~12  ⚠ no dialog        → ActionChains 在 headless 下对视口外元素点击失效
    #   13+   move target out of bounds → ActionChains 要求元素坐标在窗口范围内
    #
    # 修复：统一改用 js_click()，完全绕开 ActionChains 视口坐标限制
    # ──────────────────────────────────────────────────────────────────────────
    def extend_all_wireguard_configs(self):
        print("\n--- Starting Extend All WireGuard Configs ---")

        try:
            total = len(self.driver.find_elements(By.CSS_SELECTOR, EXTEND_BTN_SELECTOR))
        except Exception as e:
            print(f"[Extend] Failed to find buttons: {e}")
            return 0

        if total == 0:
            print("[Extend] No Extend buttons found on page.")
            return 0

        print(f"[Extend] Found {total} Extend button(s).")
        extended_count = 0

        for index in range(total):
            try:
                # 每次重新查询，防止 StaleElementReferenceException
                btns = self.driver.find_elements(By.CSS_SELECTOR, EXTEND_BTN_SELECTOR)
                if index >= len(btns):
                    print(f"[Extend] Button #{index+1} no longer in DOM, stopping.")
                    break

                btn = btns[index]

                # 读取配置名称（日志用，失败不影响续期）
                try:
                    label = btn.find_element(
                        By.XPATH,
                        "./ancestor::*[.//*[contains(text(),'Config to connect')]]"
                        "//*[contains(text(),'Config to connect')]"
                    ).text.strip()
                except Exception:
                    label = f"Config #{index + 1}"

                # ★ JS 点击，绕开 ActionChains 视口限制
                js_click(self.driver, btn)

                # 等待确认弹窗并点击确认
                try:
                    confirm_btn = WebDriverWait(self.driver, 15).until(
                        EC.element_to_be_clickable(CONFIRM_BUTTON_SELECTOR)
                    )
                    js_click(self.driver, confirm_btn)

                    WebDriverWait(self.driver, 15).until(
                        EC.invisibility_of_element_located(MODAL_BACKDROP_SELECTOR)
                    )
                    extended_count += 1
                    delay = random.randint(2, 5)
                    print(f"[Extend] ✓ ({index+1}/{total}) {label} — waiting {delay}s")
                    time.sleep(delay)

                except TimeoutException:
                    # 弹窗未出现：配置可能有冷却期，跳过
                    print(f"[Extend] ⚠ ({index+1}/{total}) {label} — no dialog, skipped")
                    try:
                        from selenium.webdriver.common.keys import Keys
                        self.driver.find_element(By.TAG_NAME, "body").send_keys(Keys.ESCAPE)
                        time.sleep(0.5)
                    except Exception:
                        pass
                    continue

            except Exception as e:
                print(f"[Extend] ✗ Config #{index+1} error: {e}")
                continue

        print(f"[Extend] Finished. {extended_count}/{total} configs extended.")
        return extended_count

    # ── WireGuard 批量下载 ─────────────────────────────────────────────────────
    def process_wireguard_downloads(self, downloaded_ids):
        print("\n--- Starting WireGuard Download Session ---")
        try:
            self.driver.execute_script("window.scrollTo(0,0)")
            time.sleep(1)

            # 切换到 WireGuard 标签
            WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable(
                (By.CSS_SELECTOR, ".flex:nth-child(4) > .mr-8:nth-child(1) > .relative"))).click()
            time.sleep(2)

            # 选择平台（第 3 个 radio）
            WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable(
                (By.CSS_SELECTOR, ".flex:nth-child(4) > .mr-8:nth-child(3) .radio-fakeradio"))).click()
            time.sleep(2)

            countries        = self.driver.find_elements(By.CSS_SELECTOR, ".mb-6 details")
            download_counter = 0

            for country in countries:
                try:
                    country_name = country.find_element(
                        By.CSS_SELECTOR, "summary"
                    ).text.split("\n")[0].strip()

                    if download_counter >= MAX_DOWNLOADS_PER_SESSION:
                        print(f"Session limit ({MAX_DOWNLOADS_PER_SESSION}) reached.")
                        return False, downloaded_ids

                    self.driver.execute_script("arguments[0].open = true;", country)
                    time.sleep(0.5)
                    rows = country.find_elements(By.CSS_SELECTOR, "tr")
                    all_configs_in_country_downloaded = True

                    for row in rows[1:]:
                        try:
                            server_id = row.find_element(
                                By.CSS_SELECTOR, "td:nth-child(1)"
                            ).text.strip()
                            if server_id in downloaded_ids:
                                continue

                            all_configs_in_country_downloaded = False
                            if download_counter >= MAX_DOWNLOADS_PER_SESSION:
                                return False, downloaded_ids

                            btn          = row.find_element(By.CSS_SELECTOR, ".button")
                            random_delay = random.randint(60, 90)

                            # ★ 改用 js_click，与续期保持一致
                            js_click(self.driver, btn)

                            confirm_btn = WebDriverWait(self.driver, 30).until(
                                EC.element_to_be_clickable(CONFIRM_BUTTON_SELECTOR)
                            )
                            js_click(self.driver, confirm_btn)

                            WebDriverWait(self.driver, 30).until(
                                EC.invisibility_of_element_located(MODAL_BACKDROP_SELECTOR)
                            )

                            download_counter += 1
                            print(f"[WG] Downloaded {server_id}. Waiting {random_delay}s...")
                            time.sleep(random_delay)
                            downloaded_ids.add(server_id)
                        except Exception:
                            continue

                    if all_configs_in_country_downloaded:
                        print(f"[WG] All configs for {country_name} done.")
                except Exception:
                    continue

        except Exception as e:
            print(f"WG Loop Error: {e}")

        return True, downloaded_ids

    # ── 整理、打包、发送 ───────────────────────────────────────────────────────
    def organize_and_send_files(self):
        print("\n###################### Organizing and Sending Files ######################")

        wg_files = {}
        for filename in os.listdir(DOWNLOAD_DIR):
            if not filename.endswith(".conf"):
                continue
            file_path    = os.path.join(DOWNLOAD_DIR, filename)
            name_no_ext  = filename.rsplit(".", 1)[0]
            clean_name   = re.sub(r"\s*\(\d+\)$", "", name_no_ext).strip().lower()
            country_code = "OTHER"
            prefix = clean_name.replace("wg-", "")
            code   = prefix.split("-")[0].split("#")[0].upper()
            if len(code) == 2 and code.isalpha():
                country_code = code
            if country_code not in wg_files:
                wg_files[country_code] = []
            wg_files[country_code].append(file_path)

        if not wg_files:
            print("No WireGuard files found.")
            return

        total_files = sum(len(v) for v in wg_files.values())
        print(f"Preparing Zip: {total_files} files across {len(wg_files)} countries.")

        zip_filename = "ProtonVPN_WireGuard_Configs.zip"
        zip_path     = os.path.join(os.getcwd(), zip_filename)

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            # 原始 .conf 按国家写入 ZIP
            for country, files in wg_files.items():
                for file_path in files:
                    archive_name = os.path.join(country, os.path.basename(file_path))
                    zipf.write(file_path, arcname=archive_name)
            # x-ui outbound JSON
            xui_total = build_xui_into_zip(DOWNLOAD_DIR, zipf)

        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            caption = (
                f"**New ProtonVPN WireGuard**\n\n"
                f"**Countries:** {len(wg_files)}\n"
                f"**.conf files:** {total_files}\n"
                f"**x-ui JSON files:** {xui_total} (IPv4 + IPv6 variants)\n\n"
                f"📁 ZIP structure:\n"
                f"`<CC>/wg-xx.conf` — WireGuard configs\n"
                f"`xui_outbounds/<CC>/<tag>.json` — x-ui outbound configs"
            )
            try:
                url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
                with open(zip_path, "rb") as doc:
                    requests.post(
                        url,
                        data={"chat_id": TELEGRAM_CHAT_ID, "caption": caption, "parse_mode": "Markdown"},
                        files={"document": doc},
                    )
                print(f"Sent {zip_filename} to Telegram.")
            except Exception as e:
                print(f"Telegram Error: {e}")

        # NOTE: os.remove(zip_path) 已永久移除，保留 ZIP 供 GitHub push 使用

        print("Cleaning up downloaded files...")
        for file in glob.glob(os.path.join(DOWNLOAD_DIR, "*")):
            os.remove(file)
        self.save_downloaded_ids(set())

    # ── 主入口 ────────────────────────────────────────────────────────────────
    def run(self, username, password):
        wg_done = False
        session = 0
        wg_ids  = self.load_downloaded_ids()

        try:
            while not wg_done and session < 20:
                session += 1
                self.setup()
                if self.login(username, password) and self.navigate_to_downloads():
                    # 先批量续期，再下载
                    self.extend_all_wireguard_configs()
                    wg_done, wg_ids = self.process_wireguard_downloads(wg_ids)
                    self.save_downloaded_ids(wg_ids)
                self.logout()
                self.teardown()

                if not wg_done:
                    print(f"Session {session} done. Re-logging in {RELOGIN_DELAY}s...")
                    time.sleep(RELOGIN_DELAY)

            self.organize_and_send_files()

        except Exception as e:
            print(f"Fatal Error: {e}")
        finally:
            self.teardown()


if __name__ == "__main__":
    U = os.environ.get("VPN_USERNAME")
    P = os.environ.get("VPN_PASSWORD")
    if U and P:
        ProtonVPN().run(U, P)
    else:
        print("Missing Credentials.")
