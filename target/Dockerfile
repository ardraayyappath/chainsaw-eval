FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        python3 \
        python3-pip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Harden sshd: key auth only, no password, no root login.
RUN mkdir -p /run/sshd \
    && sed -i \
        -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
        -e 's/^#\?PermitRootLogin.*/PermitRootLogin no/' \
        /etc/ssh/sshd_config \
    && echo "UsePAM no" >> /etc/ssh/sshd_config

# Non-root user for Chainsaw to SSH as.
RUN useradd -m -s /bin/bash eval

# Public key injected by `make keys` (copies keys/eval_key.pub here).
# The private key stays in keys/ on the host and is never baked into the image.
COPY eval_key.pub /tmp/eval_key.pub
RUN mkdir -p /home/eval/.ssh \
    && mv /tmp/eval_key.pub /home/eval/.ssh/authorized_keys \
    && chmod 700 /home/eval/.ssh \
    && chmod 600 /home/eval/.ssh/authorized_keys \
    && chown -R eval:eval /home/eval/.ssh

EXPOSE 22

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
