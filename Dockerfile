FROM alpine
RUN apk add --no-cache python3 && \
    apk add --no-cache git
RUN apk add --no-cache build-base && \
    apk add --no-cache python3-dev && \
    apk add --no-cache libffi && \
    apk add --no-cache py3-cffi && \
    apk add --no-cache automake && \
    apk add --no-cache libtool && \
    apk add --no-cache autoconf
COPY requirements.txt /
RUN pip3 install hurry.filesize
RUN pip3 install -r /requirements.txt
COPY common_analysis_yara /common_analysis_yara
RUN pip3 install -e /common_analysis_yara
ADD . /
ENTRYPOINT python3 packer_analysis_instance.py
