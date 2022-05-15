FROM aflplusplus/aflplusplus
LABEL maintainer="sergiogc5@correo.ugr.es"
LABEL url="https://github.com/Olasergiolas/TFG"

WORKDIR /AFLplusplus
RUN make distrib
RUN cd ./qemu_mode && CPU_TARGET=mipsel ./build_qemu_support.sh

RUN git clone https://gitlab.com/akihe/radamsa.git && cd radamsa && make && make install
RUN wget https://github.com/go-task/task/releases/download/v3.12.1/task_linux_amd64.deb
RUN apt update && apt install -y gdb-multiarch gcc-mipsel-linux-gnu gcc-arm-linux-gnueabi ./task_linux_amd64.deb

RUN useradd --create-home --shell /bin/bash afl
USER afl

ENV PATH="/home/afl/.local/bin:${PATH}"
RUN wget -q -O- https://bootstrap.pypa.io/get-pip.py | python

RUN mkdir /home/afl/dependencies
WORKDIR /home/afl/dependencies

RUN git clone https://github.com/AFLplusplus/unicornafl.git
WORKDIR unicornafl
RUN git submodule update --init --recursive
RUN python -m pip install -e ./unicorn/bindings/python
RUN python -m pip install -e ./bindings/python

RUN wget -O qiling.zip https://github.com/qilingframework/qiling/archive/refs/heads/dev.zip
RUN pip install --ignore-installed ./qiling.zip

WORKDIR /src