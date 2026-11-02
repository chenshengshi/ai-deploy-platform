FROM python:3.12-slim
WORKDIR /app
RUN sed -i \
      -e 's|http://deb.debian.org/debian|https://mirrors.tuna.tsinghua.edu.cn/debian|g' \
      -e 's|http://deb.debian.org/debian-security|https://mirrors.tuna.tsinghua.edu.cn/debian-security|g' \
      -e 's|http://security.debian.org/debian-security|https://mirrors.tuna.tsinghua.edu.cn/debian-security|g' \
      /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
    apt-get update && \
    apt-get install -y --no-install-recommends curl git openssh-client && \
    rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir \
      -i https://pypi.tuna.tsinghua.edu.cn/simple/ \
      --trusted-host pypi.tuna.tsinghua.edu.cn \
      -r requirements.txt
COPY app ./app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

