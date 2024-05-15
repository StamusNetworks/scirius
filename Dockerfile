# Copyright(C) 2020, Gabor Seljan
# Copyright(C) 2021, Stamus Networks
#
# Adapted by Raphaël Brogat <rbrogat@stamus-networks.com>
#
# This file comes with ABSOLUTELY NO WARRANTY!
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#Base containers
FROM python:3.9-slim-bullseye as base
RUN echo 'APT::Install-Recommends "0";' >> /etc/apt/apt.conf && \
    echo 'APT::Install-Suggests "0";' >> /etc/apt/apt.conf

#Download STEP
FROM base as source
ARG VERSION
ENV VERSION ${VERSION:-master}

ARG CYBERCHEF_VERSION
ENV CYBERCHEF_VERSION ${CYBERCHEF_VERSION:-v10.18.3}


RUN \
    echo "**** install packages ****" && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apt-utils \
        wget \
        unzip
RUN \
  echo "**** download Kibana dashboards ****" && \
  wget --no-check-certificate --content-disposition -O /tmp/kibana7-dashboards.tar.gz https://github.com/StamusNetworks/KTS7/tarball/master && \
  mkdir /tmp/kibana7-dashboards && \
  tar zxf /tmp/kibana7-dashboards.tar.gz -C /tmp/kibana7-dashboards --strip-components 1 && \
  mv /tmp/kibana7-dashboards /opt/kibana7-dashboards

RUN \
  echo "**** download Cyberchef ****" && \
  wget --no-check-certificate -O /tmp/cyberchef.zip https://github.com/gchq/CyberChef/releases/download/${CYBERCHEF_VERSION}/CyberChef_${CYBERCHEF_VERSION}.zip && \
  mkdir /tmp/cyberchef && \
  unzip /tmp/cyberchef.zip -d /tmp/cyberchef && \
  mv /tmp/cyberchef/CyberChef_${CYBERCHEF_VERSION}.html /tmp/cyberchef/index.html


RUN echo  "**** COPY Scirius ****"
COPY . /opt/scirius
RUN mv /opt/scirius/docker/scirius/scirius/local_settings.py /opt/scirius/scirius/local_settings.py
RUN chmod ugo+x /opt/scirius/docker/scirius/bin/*


# BUILD JS stuff
FROM base as build_js
RUN \
    echo "**** install packages ****" && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apt-utils && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        make \
        wget \
        gcc \
        libc-dev
RUN \
    echo "**** add NodeSource repository ****" && \
    wget -O- https://deb.nodesource.com/setup_18.x | bash -
RUN \
    echo "**** install Node.js ****" && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nodejs

COPY --from=source /opt/scirius/*.js* /opt/scirius/.eslintrc /opt/scirius/
COPY --from=source /opt/scirius/ui /opt/scirius/ui
COPY --from=source /opt/scirius/npm /opt/scirius/npm
COPY --from=source /opt/scirius/scss /opt/scirius/scss
COPY --from=source /opt/scirius/rules /opt/scirius/rules

ENV REACT_APP_HAS_ACTION 1

WORKDIR /opt/scirius
RUN echo "**** install Node.js dependencies for Scirius ****" && \
    npm install && \
    npm install -g webpack webpack-cli && \
    webpack && \
    cd ui && \
    npm install && \
    npm run build && mv webpack-stats-ui.prod.json ../rules/static/

# Install python packages
FROM base as python_modules
COPY --from=source /opt/scirius/requirements.txt /opt/scirius/requirements.txt
RUN \
  echo "**** install packages ****" && \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    gnupg2 \
    gcc \
    libc-dev \
    libsasl2-dev \
    libldap2-dev \
    libssl-dev \
    python3-pip \
    python-dev \
    git
RUN \
  echo "**** install Python dependencies for Scirius ****" && \
  cd /opt/scirius && \
  python -m pip install --user --upgrade\
    six \
    python-daemon \
    suricatactl &&\
  python -m pip install --user -r requirements.txt

FROM base as gophercap
RUN \
  echo "**** install tools to get gophercap ****" && \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    wget \
    curl \
    jq \
    gzip
RUN \
  echo "**** install gopherCap ****" && \
  cd /tmp && \
  wget -q -O gopherCap.gz $(curl --silent "https://api.github.com/repos/StamusNetworks/gophercap/releases/latest" | jq -r '.assets[] | select(.name=="gopherCap.gz") | .browser_download_url') && \
  gunzip -c gopherCap.gz > /usr/local/bin/gopherCap && \
  chmod +x /usr/local/bin/gopherCap

#BUILD doc
FROM base as build_docs
RUN \
    echo "**** install packages ****" && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apt-utils && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        make \
        gcc \
        libc-dev \
        python3-sphinx
COPY --from=source /opt/scirius/doc /opt/scirius/doc
RUN \
    echo "**** build docs ****" && \
    cd /opt/scirius/doc && \
    make html

# PACKAGING STEP
FROM base

ARG BUILD_DATE
ARG VCS_REF

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/StamusNetworks/SELKS.git" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0.0-rc1"

COPY --from=source /opt/scirius /opt/scirius

RUN \
  echo "**** install packages ****" && \
  echo "deb http://deb.debian.org/debian bullseye-backports main" > /etc/apt/sources.list.d/bullseye-backports.list && \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl \
    git \
    gunicorn && \
  DEBIAN_FRONTEND=noninteractive apt-get install -t bullseye-backports suricata -y && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir gunicorn


COPY --from=build_js /opt/scirius/rules/static /opt/scirius/rules/static
COPY --from=python_modules /root/.local /root/.local
COPY --from=gophercap /usr/local/bin/gopherCap /usr/local/bin/gopherCap
COPY --from=build_docs /opt/scirius/doc/_build/html /static/doc
COPY --from=source /opt/kibana7-dashboards /opt/kibana7-dashboards
COPY --from=source /tmp/cyberchef /static/cyberchef/



HEALTHCHECK --start-period=3m \
  CMD curl --silent --fail http://127.0.0.1:8000 || exit 1

VOLUME /rules /data /static /logs

EXPOSE 8000

ENTRYPOINT ["/bin/bash", "/opt/scirius/docker/scirius/bin/start-scirius.sh"]
