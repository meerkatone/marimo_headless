FROM archlinux:latest
ENV TZ=Europe/London

RUN pacman -Syu --noconfirm
RUN pacman -S --noconfirm --needed uv zip unzip 7zip git upx jdk-openjdk python3 lldb curl wget zsh binwalk squashfs-tools

ENV VIRTUAL_ENV=/opt/headless
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN uv venv /opt/headless --python 3.11
RUN source /opt/headless/bin/activate
RUN uv pip install marimo polars altair duckdb pyarrow fastparquet numpy==1.23.5 matplotlib pandas pwntools angr angr-management z3-solver seaborn plotly scikit-learn bokeh==2.4.3 statsmodels scipy ropper keystone-engine pyghidra monkeyhex pyvex bingraphvis angr-utils cfg-explorer

WORKDIR /opt/src
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.2_build/ghidra_11.4.2_PUBLIC_20250826.zip
RUN unzip ./ghidra_11.4.2_PUBLIC_20250826.zip
ENV GHIDRA_INSTALL_DIR="/opt/src/ghidra_11.4.2_PUBLIC/"
RUN uv pip install --upgrade pip
RUN git clone https://github.com/mandiant/capa.git
WORKDIR /opt/src/capa
RUN git submodule update --init --recursive
RUN uv pip install -e .

WORKDIR /local
EXPOSE 2718
ENTRYPOINT ["marimo", "edit", "--host", "0.0.0.0"]
