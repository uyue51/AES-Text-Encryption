# 







































import os
import getpass
import platform
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import random
import string

# 跨平台清屏函数
def clear_screen():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

# 确保加密目录、秘钥目录和解密目录存在
encrypt_dir = os.path.join(os.path.dirname(__file__), '加密')
key_dir = os.path.join(os.path.dirname(__file__), '秘钥')
decrypt_dir = os.path.join(os.path.dirname(__file__), '解密')
if not os.path.exists(encrypt_dir):
    os.makedirs(encrypt_dir)
if not os.path.exists(key_dir):
    os.makedirs(key_dir)
if not os.path.exists(decrypt_dir):
    os.makedirs(decrypt_dir)

def pad(data):
    """对数据进行填充，使其长度为AES块大小的整数倍"""
    block_size = AES.block_size
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    """去除填充"""
    return data[:-data[-1]]

def generate_random_key():
    """生成一个512位的随机秘钥"""
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=64))

def encrypt_text(text, secret_key, save_key_file=False):
    """使用AES算法加密文本，可选择是否保存秘钥文件"""
    salt = get_random_bytes(16)
    key = PBKDF2(secret_key, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8')))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    encrypted_content = salt + iv.encode('utf-8') + ct.encode('utf-8')

    if save_key_file:
        key_filename = input("请输入秘钥文件的文件名（不包括扩展名）: ")
        key_filename = f"{key_filename}.key"
        key_filepath = os.path.join(key_dir, key_filename)
        counter = 1
        while os.path.exists(key_filepath):
            base, ext = os.path.splitext(key_filename)
            key_filename = f"{base}_{counter}{ext}"
            key_filepath = os.path.join(key_dir, key_filename)
            counter += 1
        with open(key_filepath, 'wb') as f:
            f.write(secret_key.encode('utf-8'))
        print(f"秘钥已保存到 {key_filepath}")

    return encrypted_content

def encrypt_menu():
    """加密菜单函数，处理秘钥选择逻辑"""
    text_to_encrypt = input("请输入需要加密的文本: ")
    
    # 秘钥选择
    print("""
    秘钥选择菜单
    (1) 使用自定义秘钥
    (2) 生成随机秘钥
    """)
    choice = input("请选择秘钥方式: ")
    
    if choice == '1':
        secret_key = getpass.getpass("请输入加密秘钥: ")
        save_key_file = input("是否保存秘钥文件？(y/n): ").strip().lower() == 'y'
    elif choice == '2':
        secret_key = generate_random_key()
        print("生成的随机秘钥为：", secret_key)
        save_key_file = input("是否保存随机生成的秘钥文件？(y/n): ").strip().lower() == 'y'
    else:
        print("无效选择，请重试。")
        return encrypt_menu()  # 递归调用直到输入有效
    
    filename = input("请输入加密文件的文件名（不包括扩展名）: ")
    filename = f"{filename}.txt"
    filepath = os.path.join(encrypt_dir, filename)
    counter = 1
    while os.path.exists(filepath):
        base, ext = os.path.splitext(filename)
        filename = f"{base}_{counter}{ext}"
        filepath = os.path.join(encrypt_dir, filename)
        counter += 1
    
    # 清屏后再加密并保存文件
    clear_screen()
    encrypted_content = encrypt_text(text_to_encrypt, secret_key, save_key_file)
    with open(filepath, 'wb') as f:
        f.write(encrypted_content)
    print(f"加密完成！加密后的文件已保存到 {filepath}")

def decrypt_text_menu():
    """解密菜单函数"""
    print("""
    解密选项
    (1) 输入秘钥
    (2) 使用秘钥文件
    """)
    choice = input("请选择解密方式: ")

    if choice == '1':
        secret_key = getpass.getpass("请输入解密秘钥: ")
        return secret_key
    elif choice == '2':
        key_filename = input("请输入秘钥文件的文件名（包括.key扩展名）: ")
        key_filepath = os.path.join(key_dir, key_filename)
        if os.path.isfile(key_filepath):
            with open(key_filepath, 'r') as f:
                secret_key = f.read().strip()
            return secret_key
        else:
            print("无效的秘钥文件，请重试。")
            return decrypt_text_menu()  # 递归调用直到输入有效
    else:
        print("无效选择，请重试。")
        return decrypt_text_menu()  # 递归调用直到输入有效

def decrypt_text(encrypted_content, secret_key):
    """使用AES算法解密文本"""
    try:
        salt = encrypted_content[:16]
        iv = base64.b64decode(encrypted_content[16:16+24].decode('utf-8'))
        ct = base64.b64decode(encrypted_content[16+24:].decode('utf-8'))
        key = PBKDF2(secret_key, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct))
        return pt.decode('utf-8')
    except Exception as e:
        print("解密失败，请检查秘钥是否正确。")
        return None

def show_menu():
    """显示加密/解密菜单"""
    print("""
    加密/解密菜单
    (1) 加密
    (2) 解密
    (3) 退出
    """)

def main():
    while True:
        clear_screen()
        show_menu()
        choice = input("请选择操作: ")

        if choice == '1':
            encrypt_menu()
            input("按回车键继续...")

        elif choice == '2':
            default_path = os.path.join(os.path.dirname(__file__), '加密')
            filepath = input(f"请输入要解密的文件路径（默认路径：{default_path}，只需输入文件名和拓展名）: ")
            if not os.path.isabs(filepath):
                filepath = os.path.join(default_path, filepath)

            secret_key = decrypt_text_menu()
            if secret_key:
                try:
                    with open(filepath, 'rb') as f:
                        encrypted_content = f.read()
                    decrypted_text = decrypt_text(encrypted_content, secret_key)
                    if decrypted_text:
                        decrypt_filename = input("请输入解密后的文件名（不包括扩展名）: ")
                        decrypt_filename = f"{decrypt_filename}.txt"
                        decrypt_filepath = os.path.join(decrypt_dir, decrypt_filename)
                        counter = 1
                        while os.path.exists(decrypt_filepath):
                            base, ext = os.path.splitext(decrypt_filename)
                            decrypt_filename = f"{base}_{counter}{ext}"
                            decrypt_filepath = os.path.join(decrypt_dir, decrypt_filename)
                            counter += 1

                        with open(decrypt_filepath, 'w') as f:
                            f.write(decrypted_text)
                        print(f"解密完成！解密后的文本已保存到 {decrypt_filepath}")

                except FileNotFoundError:
                    print(f"文件 {filepath} 未找到，请检查路径是否正确。")

             # 解密完成后自动跳转回菜单
                input("按回车键继续...")

        elif choice == '3':
            print("退出程序。")
            break

        else:
            print("无效选择，请重试。")

if __name__ == "__main__":
    main()