import os
import sys
import json
import socket
import threading
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import subprocess
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.listview import ListView
from kivy.adapters.listadapter import ListAdapter

# --- 핵심 통신 모듈 ---
class P2PNetwork:
    def __init__(self):
        self.key_pair = ec.generate_private_key(ec.SECP384R1())
        self.shared_keys = {}  # {ip: session_key}
        self.peers = {}
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.bind(('0.0.0.0', 5555))
        threading.Thread(target=self.listen, daemon=True).start()

    # 공개키 문자열 반환
    def get_public_key_str(self):
        return self.key_pair.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()

    # 세션키 도출
    def derive_shared_key(self, peer_pub_str):
        peer_key = load_pem_public_key(peer_pub_str.encode())
        shared_secret = self.key_pair.exchange(ec.ECDH(), peer_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'chat',
        ).derive(shared_secret)

    # AES-GCM 암호화
    def encrypt(self, key, plaintext):
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv)
        ).encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

    # AES-GCM 복호화
    def decrypt(self, key, data):
        raw = base64.b64decode(data)
        iv, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag)
        ).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    # 주변 기기 검색
    def discover(self):
        msg = json.dumps({"type": "discover", "pub_key": self.get_public_key_str()})
        self.socket.sendto(msg.encode(), ('<broadcast>', 5555))

    # 메시지 수신 대기
    def listen(self):
        while True:
            data, addr = self.socket.recvfrom(4096)
            self.handle_message(data.decode(), addr)

    # 메시지 전송
    def send(self, message, peer_ip):
        if peer_ip in self.shared_keys:
            message = self.encrypt(self.shared_keys[peer_ip], message)
        self.socket.sendto(message.encode(), (peer_ip, 5555))

    # 메시지 처리
    def handle_message(self, message, addr):
        try:
            msg = json.loads(message)
            if msg['type'] == 'discover':
                response = {
                    'type': 'discover_response',
                    'pub_key': self.get_public_key_str(),
                    'ip': addr[0]
                }
                self.send(json.dumps(response), addr[0])
            elif msg['type'] == 'discover_response':
                self.shared_keys[addr[0]] = self.derive_shared_key(msg['pub_key'])
                self.peers[addr[0]] = msg['pub_key']
                print(f"[+] {addr[0]} 연결됨 (세션 키 생성)")
        except Exception:
            if addr[0] in self.shared_keys:
                try:
                    plain = self.decrypt(self.shared_keys[addr[0]], message)
                    print(f"{addr[0]}: {plain.decode()}")
                except Exception as e:
                    print(f"복호화 실패: {e}")

# --- Kivy UI ---
class DecentralChatApp(App):
    def build(self):
        self.network = P2PNetwork()
        self.setup_ui()
        return self.layout

    def setup_ui(self):
        self.layout = BoxLayout(orientation='vertical')
        
        # 탐색 버튼
        self.scan_btn = Button(text='근처 사용자 탐색', size_hint=(1, 0.1))
        self.scan_btn.bind(on_press=self.scan_devices)
        
        # 기기 목록
        self.devices_adapter = ListAdapter(data=[], cls=Label)
        self.devices_list = ListView(adapter=self.devices_adapter)
        
        # 채팅 메시지
        self.chat_adapter = ListAdapter(data=[], cls=Label)
        self.chat_list = ListView(adapter=self.chat_adapter)
        
        # 메시지 입력
        self.msg_input = TextInput(hint_text='메시지 입력', size_hint=(1, 0.1))
        send_btn = Button(text='전송', size_hint=(0.2, 0.1))
        send_btn.bind(on_press=self.send_message)
        
        # UI 구성
        input_layout = BoxLayout(size_hint=(1, 0.1))
        input_layout.add_widget(self.msg_input)
        input_layout.add_widget(send_btn)
        
        self.layout.add_widget(self.scan_btn)
        self.layout.add_widget(Label(text='연결 가능한 디바이스:'))
        self.layout.add_widget(self.devices_list)
        self.layout.add_widget(Label(text='채팅 메시지:'))
        self.layout.add_widget(self.chat_list)
        self.layout.add_widget(input_layout)

    def scan_devices(self, instance):
        self.network.discover()
        self.devices_adapter.data = [ip for ip in self.network.peers.keys()]
        self.devices_list._trigger_reset_populate()

    def send_message(self, instance):
        msg = self.msg_input.text
        if msg and self.network.peers:
            target_ip = list(self.network.peers.keys())[0]
            self.network.send(msg, target_ip)
            self.chat_adapter.data.append(f"나: {msg}")
            self.chat_list._trigger_reset_populate()
            self.msg_input.text = ''

# --- APK 빌드 ---
def build_apk():
    print("APK 빌드를 시작합니다...")
    if not os.path.exists('buildozer.spec'):
        subprocess.run(['buildozer', 'init'])
    requirements = ['kivy', 'cryptography', 'python-for-android']
    subprocess.run(['pip', 'install'] + requirements)
    subprocess.run(['buildozer', '-v', 'android', 'debug'])
    print("빌드 완료! output/bin 디렉토리에서 APK 확인")

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'build':
        build_apk()
    else:
        DecentralChatApp().run()
