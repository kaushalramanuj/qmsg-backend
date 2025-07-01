FROM python:3.11

WORKDIR /app

# Install build tools for liboqs-python
RUN apt-get update && apt-get install -y cmake build-essential git

# Build and install liboqs C library
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=/opt/oqs && \
    cmake --build /tmp/liboqs/build --parallel 4 && \
    cmake --build /tmp/liboqs/build --target install && \
    rm -rf /tmp/liboqs

# Set environment variable so liboqs-python can find the library
ENV OQS_INSTALL_PATH=/opt/oqs

# Copy requirements and local liboqs-python source
COPY requirements.txt .
COPY liboqs-python ./liboqs-python

# Install dependencies (including local liboqs-python)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the backend code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]