FROM archlinux:latest
ENV TZ=Europe/London

RUN pacman -Syu --noconfirm --disable-sandbox

# Ghidra 12.1 is built/tested against JDK 21 LTS. Newer JDKs (e.g. OpenJDK 26)
# cause native instability with PyGhidra's embedded JVM, so pin JDK 21 explicitly.
RUN pacman -S --noconfirm --needed --disable-sandbox uv zip unzip 7zip git upx jdk21-openjdk python3 lldb curl wget zsh binwalk squashfs-tools

# Make JDK 21 the JVM PyGhidra picks up.
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV PATH="$JAVA_HOME/bin:$PATH"

ENV VIRTUAL_ENV=/opt/headless
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN uv venv /opt/headless --python 3.13
RUN source /opt/headless/bin/activate
RUN uv pip install marimo polars altair duckdb pyarrow fastparquet quak moterm moutils tqdm rich mohtml vegafusion vl-convert-python sqlglot numpy matplotlib pandas pwntools angr angr-management z3-solver seaborn plotly scikit-learn bokeh statsmodels scipy ropper keystone-engine pyghidra pyghidra-mcp monkeyhex pyvex bingraphvis angr-utils cfg-explorer

WORKDIR /opt/src
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip
RUN unzip ./ghidra_12.1.2_PUBLIC_20260605.zip

ENV GHIDRA_INSTALL_DIR="/opt/src/ghidra_12.1.2_PUBLIC/"
RUN uv pip install --upgrade pip
RUN git clone https://github.com/mandiant/capa.git
WORKDIR /opt/src/capa
RUN git submodule update --init --recursive
RUN uv pip install -e .

WORKDIR /local
EXPOSE 2718
ENTRYPOINT ["marimo", "edit", "--host", "0.0.0.0"]
