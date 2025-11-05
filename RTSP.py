import cv2
import tkinter as tk
from PIL import Image, ImageTk
import threading
import time
from collections import deque

# RTSP 地址列表

RTSP_URLS = [
    "rtsp://admin:12345@172.20.13.245/h264/ch42/main/av_stream",  # 1
    "rtsp://admin:yy123456@172.20.13.252/h264/ch42/main/av_stream",  # 2
    "rtsp://admin:12345@172.20.13.241/h264/ch34/main/av_stream",  # 3
    "rtsp://admin:yy123456@172.20.13.252/h264/ch39/main/av_stream",  # 4
    "rtsp://admin:yy123456@172.20.13.252/h264/ch41/main/av_stream",  # 5
    "rtsp://admin:yy123456@172.20.13.252/h264/ch33/main/av_stream",  # 6
    "rtsp://admin:12345@172.20.13.247/h264/ch39/main/av_stream",  # 7
    "rtsp://admin:yy123456@172.20.13.251/h264/ch45/main/av_stream",  # 8
    "rtsp://admin:yy123456@172.20.13.252/h264/ch44/main/av_stream",  # 9
]

class VideoStream:
    def __init__(self, url, target_width=None, target_height=None, max_fps=30):
        # 强制使用 FFmpeg 后端，提高兼容性
        self.cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
        self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 2)  # 缓冲帧数，减少延迟

        # 可选降低解码分辨率，减轻 CPU
        if target_width and target_height:
            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, target_width)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, target_height)

        self.frame_buffer = deque(maxlen=5)  # 缓存最新5帧，避免丢帧
        self.running = True
        self.max_fps = max_fps
        self.thread = threading.Thread(target=self.update, daemon=True)
        self.thread.start()

    def update(self):
        interval = 1 / self.max_fps
        while self.running:
            start = time.time()
            ret, frame = self.cap.read()
            if ret:
                self.frame_buffer.append(frame)
            elapsed = time.time() - start
            sleep_time = interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

    def read(self):
        return self.frame_buffer[-1] if self.frame_buffer else None

    def release(self):
        self.running = False
        if self.cap.isOpened():
            self.cap.release()


class MultiRTSPPlayer:
    def __init__(self, root, urls):
        self.root = root
        self.root.title("KingSan专用")
        self.root.geometry("720x450")

        self.streams = [VideoStream(url) for url in urls]
        self.labels = []
        self.fullscreen = False
        self.focus_index = None

        # 创建 3x3 网格
        for i in range(3):
            for j in range(3):
                label = tk.Label(root, bg="black")
                label.grid(row=i, column=j, sticky="nsew", padx=1, pady=1)
                idx = i * 3 + j
                label.bind("<Button-1>", lambda e, index=idx: self.toggle_fullscreen(index))
                self.labels.append(label)

        # 自动拉伸
        for i in range(3):
            self.root.rowconfigure(i, weight=1)
            self.root.columnconfigure(i, weight=1)

        self.update_frames()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def update_frames(self):
        if self.fullscreen and self.focus_index is not None:
            frame = self.streams[self.focus_index].read()
            if frame is not None:
                frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                img = Image.fromarray(frame)
                img = img.resize((self.root.winfo_width(), self.root.winfo_height()))
                imgtk = ImageTk.PhotoImage(image=img)
                self.labels[self.focus_index].imgtk = imgtk
                self.labels[self.focus_index].config(image=imgtk)
        else:
            width = max(1, self.root.winfo_width() // 3)
            height = max(1, self.root.winfo_height() // 3)
            for i, stream in enumerate(self.streams):
                if i >= 9:
                    break
                frame = stream.read()
                if frame is not None:
                    frame = cv2.resize(frame, (width, height))
                    frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    img = Image.fromarray(frame)
                    imgtk = ImageTk.PhotoImage(image=img)
                    self.labels[i].imgtk = imgtk
                    self.labels[i].config(image=imgtk)

        # 使用更高刷新率，30fps
        self.root.after(33, self.update_frames)

    def toggle_fullscreen(self, index):
        if self.fullscreen:
            # 退出全屏
            self.fullscreen = False
            self.focus_index = None
            for i, label in enumerate(self.labels):
                label.grid(row=i // 3, column=i % 3, sticky="nsew", padx=1, pady=1)
        else:
            # 进入全屏
            self.fullscreen = True
            self.focus_index = index
            for i, label in enumerate(self.labels):
                if i == index:
                    label.grid(row=0, column=0, sticky="nsew")
                else:
                    label.grid_forget()

    def on_close(self):
        for stream in self.streams:
            stream.release()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    player = MultiRTSPPlayer(root, RTSP_URLS)
    root.mainloop()
