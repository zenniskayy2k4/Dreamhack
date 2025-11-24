FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build pkg-config \
      libstdc++6 libgomp1 curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

ENV PIP_NO_BUILD_ISOLATION=1 \
    CMAKE_BUILD_PARALLEL_LEVEL=2 \
    PIP_DEFAULT_TIMEOUT=120

RUN pip install --no-cache-dir --upgrade pip \
    setuptools wheel scikit-build-core pybind11 cmake ninja flit-core \
    "typing-extensions>=4.5" "numpy==2.3.2"

RUN pip install --no-cache-dir --no-build-isolation --no-binary=:all: \
      "llama-cpp-python==0.2.90" \
      --config-settings=cmake.define.GGML_NATIVE=OFF \
      --config-settings=cmake.define.GGML_CPU=ON \
      --config-settings=cmake.define.GGML_AVX=ON \
      --config-settings=cmake.define.GGML_AVX2=OFF \
      --config-settings=cmake.define.GGML_F16C=OFF \
      --config-settings=cmake.define.GGML_FMA=OFF \
      --config-settings=cmake.define.GGML_OPENMP=ON

RUN pip install --no-cache-dir flask==3.1.1 requests==2.32.5

WORKDIR /app
COPY app.py index.html style.css flag.txt /app/

RUN mkdir -p /opt/model && \
    curl -L --fail --retry 5 --retry-delay 2 \
      -o /opt/model/tinyllama.gguf \
      https://huggingface.co/tnvj123/tinyllama-1.1b-chat-v1.0.Q3_K_S.gguf/resolve/main/tinyllama-1.1b-chat-v1.0.Q3_K_S.gguf && \
    echo "6d58c8fbdaa822b004d7ba473f9b9ad4d1ef7c2dd2c4cf9f9856451aa44bf0ca  /opt/model/tinyllama.gguf" | sha256sum -c -

ENV MODEL_PATH=/opt/model/tinyllama.gguf

ENV PORT=5000 \
    LLAMA_CTX=512 LLAMA_THREADS=2 LLAMA_BATCH=64 \
    OMP_NUM_THREADS=2 KMP_AFFINITY=disabled MALLOC_ARENA_MAX=2 \
    PRELOAD=1

EXPOSE 5000
CMD ["python", "app.py"]
