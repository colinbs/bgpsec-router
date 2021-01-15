FROM archlinux

RUN pacman -Sy archlinux-keyring --noconfirm \
    && pacman -Syyu --noconfirm \
    && pacman -S --noconfirm --needed git python

RUN git clone https://git.csames.de/colin/bgpsec-router.git \
    && cd bgpsec-router

#CMD ["/bgpsec-router/router.py", "0.0.0.0", "179", "172.17.0.100"]
