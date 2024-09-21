import itertools
import string
import os

# 定义字符集
digits = list(string.digits)  # 0-9
lowercase = list(string.ascii_lowercase)  # a-z
uppercase = list(string.ascii_uppercase)  # A-Z
symbols = list(string.punctuation)  # 标准符号

# 合并所有字符
all_chars = digits + lowercase + uppercase + symbols

# 输出文件大小限制（字节）
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def get_password_generator(length):
    """生成指定长度的密码组合"""
    return itertools.product(all_chars, repeat=length)

def write_passwords_to_files(length):
    """将生成的密码写入文件，并确保每个文件不超过5MB"""
    generator = get_password_generator(length)
    file_index = 1
    filename = f"{length}.txt"
    current_size = 0
    file = open(filename, 'w', encoding='utf-8')

    for password_tuple in generator:
        password = ''.join(password_tuple)
        line = password + '\n'
        line_size = len(line.encode('utf-8'))

        if current_size + line_size > MAX_FILE_SIZE:
            file.close()
            file_index += 1
            filename = f"{length}_{file_index}.txt"
            file = open(filename, 'w', encoding='utf-8')
            current_size = 0

        file.write(line)
        current_size += line_size

    file.close()
    print(f"完成长度为{length}的密码生成，生成了{file_index}个文件。")

def main():
    for length in range(1, 13):  # 1到12位
        print(f"正在生成长度为{length}的密码...")
        write_passwords_to_files(length)

if __name__ == "__main__":
    main()