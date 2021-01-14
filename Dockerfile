FROM archlinux/base

RUN pacman -Sy archlinux-keyring --noconfirm \
    && pacman -Syyu --noconfirm \
    && pacman -S --noconfirm --needed git python

RUN git clone https://git.csames.de/colin/bgpsec-router.git \
    && mkdir /keys \
    && cd rpki-cache \
    && ./gen-keys 100 /keys

CMD ["/bgpsec-router/router.py", "0.0.0.0", "179", "172.18.0.2"]
