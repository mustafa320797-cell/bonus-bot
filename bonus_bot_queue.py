import asyncio, configparser, os, re
from telethon import TelegramClient, events
from telethon.errors import FloodWaitError
from urllib.parse import urlparse
import aiohttp
import requests
import datetime

# Konfigürasyon
config = configparser.ConfigParser()
config.read('config.ini')
api_id = int(config['Telegram']['api_id'])
api_hash = config['Telegram']['api_hash']

source_chats = [
    '@BonusSoftResmi',
    '@BAMCOOKOD',
    '@bonusuzmanikod',
    '@bonusmadeni',
    '@KODTIMEDUYURU',
    '@kodvegas',
    '@bonusbing',
    '@promokodcutayfaa'
]
target_chat = '@jokerbonuskod'

# Kara liste & dosyalar
blacklist = set(word.strip().lower() for word in config['Filter']['blacklist'].split(','))
sent_codes_file = 'sent_codes.txt'
sent_msg_file = 'sent_message_ids.txt'

sent_codes = set()
sent_msg_ids = set()
file_lock = asyncio.Lock()
queue = asyncio.Queue()

BLACKLIST_DOMAINS = ['about:blank', 'localhost', 'example.com', '127.0.0.1', '0.0.0.0']

def load_persistent_data():
    if os.path.exists(sent_codes_file):
        with open(sent_codes_file, 'r', encoding='utf-8') as f:
            sent_codes.update(line.strip().lower() for line in f)
    if os.path.exists(sent_msg_file):
        with open(sent_msg_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    chat_id, msg_id = map(int, line.strip().split(':'))
                    sent_msg_ids.add((chat_id, msg_id))
                except:
                    continue

async def save_msg_id(chat_id, msg_id):
    async with file_lock:
        with open(sent_msg_file, 'a', encoding='utf-8') as f:
            f.write(f"{chat_id}:{msg_id}\n")
        sent_msg_ids.add((chat_id, msg_id))

async def save_code(code):
    async with file_lock:
        code_lower = code.lower()
        if code_lower not in sent_codes:
            with open(sent_codes_file, 'a', encoding='utf-8') as f:
                f.write(code + '\n')
            sent_codes.add(code_lower)

client = TelegramClient('session', api_id, api_hash)
CODE_REGEX = re.compile(r'^(?!-+$)[A-ZÇĞİÖŞÜ0-9\-]{5,30}$', re.IGNORECASE)

def extract_clickable_codes(message):
    codes = []
    if not message.entities:
        return codes
    for entity in message.entities:
        if entity.__class__.__name__ == 'MessageEntityCode':
            raw = message.message[entity.offset:entity.offset + entity.length]
            clean = re.sub(r'[\s\r\n]+', '', raw).strip()
            if clean.lower() not in blacklist and CODE_REGEX.match(clean):
                codes.append(clean)
    return list(dict.fromkeys(codes))

def find_https_link(text):
    matches = re.findall(r'https?://[^\s<>()\[\]{}]+', text or '')
    return matches[0] if matches else ''

async def resolve_redirect(url):
    final_url = None
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    REDIRECT_DOMAINS = ['bit.ly', 'rebrand.ly', 'shrtco.de', 't2m.io', 'cutt.ly', 'get-link.co']

    if any(d in domain for d in REDIRECT_DOMAINS):
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, allow_redirects=True)
            if response.status_code == 200:
                final_url = response.url
                return final_url
        except Exception:
            return None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                if resp.status == 200:
                    final_url = str(resp.url)
    except Exception:
        return None

    if not final_url:
        return None

    parsed_final = urlparse(final_url)
    if not parsed_final.scheme.startswith("http") or not parsed_final.netloc:
        return None

    if any(bad in parsed_final.netloc for bad in BLACKLIST_DOMAINS):
        return None

    return final_url

def clean_link(url):
    try:
        parsed = urlparse(url)
        if not parsed.scheme.startswith('http') or not parsed.netloc:
            return url
        domain = f"{parsed.scheme}://{parsed.netloc}"
        for ext in ['.com', '.net', '.org', '.bet', '.in', '.co', '.io', '.site']:
            if ext in domain:
                cut_index = domain.find(ext) + len(ext)
                return domain[:cut_index]
        return domain
    except Exception:
        return url

@client.on(events.NewMessage(chats=source_chats))
async def handler(event):
    await queue.put(event)

async def worker():
    while True:
        event = await queue.get()
        try:
            await process_message(event)
        except Exception as e:
            print("[HATA]", e)
        queue.task_done()

async def process_message(event):
    chat_id = event.chat_id
    msg_id = event.message.id

    if (chat_id, msg_id) in sent_msg_ids:
        return

    codes = extract_clickable_codes(event.message)
    if not codes:
        return

    short_link = find_https_link(event.message.message)
    if not short_link:
        return

    resolved_link = await resolve_redirect(short_link)
    if not resolved_link:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [Uyarı] Mesaj {msg_id} içinde geçersiz veya çözülemeyen link: {short_link}")
        print(f"[{timestamp}] Mesaj içeriği:\n{event.message.message}\n")
        return

    resolved_link = clean_link(resolved_link)

    new_codes = []
    for c in codes:
        if c.lower() not in sent_codes:
            new_codes.append(c)
            sent_codes.add(c.lower())

    if not new_codes:
        return

    text = "\n".join(f"`{c}`" for c in new_codes)
    text += f"\n\n{resolved_link}"

    try:
        await client.send_message(target_chat, text, parse_mode='md', link_preview=False)
        for code in new_codes:
            await save_code(code)
        await save_msg_id(chat_id, msg_id)
    except FloodWaitError as e:
        print(f"[FLOOD] Bekleniyor: {e.seconds}s")
        await asyncio.sleep(e.seconds)
        try:
            await client.send_message(target_chat, text, parse_mode='md', link_preview=False)
            for code in new_codes:
                await save_code(code)
            await save_msg_id(chat_id, msg_id)
        except Exception as err:
            print(f"[YENİDEN HATA] {err}")

# ✅ Worker sayısı artırıldı (10)
async def main():
    load_persistent_data()
    await client.start()
    print("🚀 Bot başlatıldı, kuyruk bekleniyor...")
    for _ in range(10):
        asyncio.create_task(worker())
    await client.run_until_disconnected()

if __name__ == '__main__':
    asyncio.run(main())