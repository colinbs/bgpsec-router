FROM archlinux

RUN pacman -Sy archlinux-keyring --noconfirm \
    && pacman -Syyu --noconfirm \
    && pacman -S --noconfirm --needed git python base-devel cmake

#RUN git clone https://github.com/colinbs/rtrlib.git \
#    && cd rtrlib \
#    && mkdir build \
#    && cd build \
#    && git checkout bgpsec-temp \
#    && cmake -D CMAKE_BUILD_TYPE=Debug -D CMAKE_INSTALL_PREFIX=/usr .. \
#    && make \
#    && make install \
#    && cd /
#
#RUN git clone https://github.com/colinbs/bgpsec-path-gen.git \
#    && cd bgpsec-path-gen \
#    && mkdir build \
#    && cd build \
#    && cmake -D CMAKE_BUILD_TYPE=Debug .. \
#    && make \
#    && cd /

RUN git clone https://git.csames.de/colin/bgpsec-router.git \
    && cd bgpsec-router

ADD setup.sh /setup.sh
ADD spki-cache/ /spki-cache/

#CMD ["/bgpsec-router/router.py", "0.0.0.0", "179", "172.17.0.100"]
