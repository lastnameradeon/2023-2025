import os

intput_file = 'www_jd_com_12g.txt'
output_dir = 'C://Users//PTSH//Desktop//3Gstudent//Homework-of-Python//SRC'



def split_large_file(input_file, output_dir, chunk_size=10 * 1024 * 1024):  # 10MB chunk size
    """
    将大文件拆分成多个小文件

    参数:
    input_file (str): 输入文件的路径
    output_dir (str): 输出文件的目录
    chunk_size (int): 每个输出文件的大小(以字节为单位), 默认为 10MB
    """
    os.makedirs(output_dir, exist_ok=True)

    file_count = 1
    with open(input_file, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            output_file = os.path.join(output_dir, f'output_file_{file_count:03d}.txt')
            with open(output_file, 'wb') as out_f:
                out_f.write(chunk)

            file_count += 1

    print(f"文件已成功拆分为 {file_count - 1} 个小文件, 保存在 {output_dir} 目录下。")


def split_large_file_2(input_file, output_dir, chunk_size=10 * 1024 * 1024):
    """
    将大文件拆分成多个小文件

    参数:
    input_file (str): 输入文件的路径
    output_dir (str): 输出文件的目录
    chunk_size (int): 每个输出文件的大小(以字节为单位), 默认为 10MB
    """
    os.makedirs(output_dir, exist_ok=True)

    file_count = 1
    with open(input_file, 'r', encoding='utf-8') as f:
        current_chunk = ''
        current_size = 0

        for line in f:
            line_size = len(line.encode('utf-8'))  # 计算行的字节大小
            if current_size + line_size > chunk_size:
                # 写入当前块到文件
                output_file = os.path.join(output_dir, f'output_file_{file_count:03d}.txt')
                with open(output_file, 'w', encoding='utf-8') as out_f:
                    out_f.write(current_chunk)

                file_count += 1
                current_chunk = line  # 开始新的块
                current_size = line_size
            else:
                current_chunk += line
                current_size += line_size

                # 写入最后一块
        if current_chunk:
            output_file = os.path.join(output_dir, f'output_file_{file_count:03d}.txt')
            with open(output_file, 'w', encoding='utf-8') as out_f:
                out_f.write(current_chunk)

    print(f"文件已成功拆分为 {file_count} 个小文件, 保存在 {output_dir} 目录下。")


a = split_large_file(intput_file, output_dir)

