#!/bin/bash
set -e

SCIRIUS_DIR=/home/selks-user/scirius
SCIRIUS_DOCKER_DIR=/opt/scirius
SELKS_DIR=/opt/selksd/SELKS/docker
MANAGE="/usr/local/bin/python3 /opt/scirius/manage.py"

host=""
dev=0
docker=0
sync=0
scirius_postsync=0
dev_ui=0
build_ui=0

cd "$(dirname "$0")"/..

function show_usage()
{
    cat << EOF >&2
Usage: $0 [options...] <username@ssh_ip>

Options:
    -h, --help

    One shot actions:
    -d, --dev               Install dev dependencies
    -u, --dev-ui            Install UI dev dependencies/build the UI
    -D, --docker            Rebuild Docker image

    Code updates:

    -s, --sync              Sync code
    -R, --restart-scirius   Restart scirius
    -o, --scirius-postsync  Build/install migrations, restart Scirius
    -r, --build-ui          BUild ui bundle


Breaks your Selks.
EOF
    exit 1
}

set -x
while [[ $# -gt 0 ]]
do
    key="$1"

    case $key in
    -h|--help)
        show_usage
        exit 1
        ;;
    -d|--dev)
        sync=1
        dev=1
        ;;
    -u|--dev-ui)
        dev_ui=1
        ;;
    -s|--sync)
        sync=1
        ;;
    -D|--docker)
        docker=1
        ;;
    -r|--build-ui)
        build_ui=1
        ;;
    -o|--scirius-postsync)
        scirius_postsync=1
        ;;
    *)
        host="$1"
        ;;
    esac
    shift # past argument or value
done

if [ "$host" == "" ]
then
    show_usage
    exit 1
fi

if ! ssh "$host" true
then
    echo "SSH connection failed" >&2
    exit 1
fi

set -x

if [ "$dev" == 1 ]
then
    ssh "$host" "sudo -S bash -x -c 'test -e /etc/sudoers.d/selks-user || echo selks-user\ ALL=NOPASSWD:\ ALL > /etc/sudoers.d/selks-user'"
fi

if [ "$sync" == 1 ]
then
    rsync -v -a -e ssh --chmod=ugo=rwX --exclude=.git --exclude=\*.swp --exclude=venv --exclude=vprod --exclude=db* --exclude=generated --exclude=git-sources --exclude=node_modules --exclude=tests/robotframework --rsync-path="sudo rsync" ./ "$host":$SCIRIUS_DIR
    rsync -v -a -e ssh --chmod=ugo=rwX --rsync-path="sudo rsync" ./docker/scirius/scirius/local_settings.py "$host":$SCIRIUS_DIR/scirius/
fi

if [ "$docker" == 1 ]
then
    ssh "$host" "sudo docker build -t build -t ghcr.io/stamusnetworks/scirius:master $SCIRIUS_DIR"
fi

if [ "$dev" == 1 ]
then
    # Pip dependencies
    ssh "$host" "sudo bash -x -c 'cd $SELKS_DIR ; grep -q /home/selks-user/scirius docker-compose.yml || (sed -e \"/scirius-data:\/data\//a \ \ \ \ \ \ - /home/selks-user/scirius:$SCIRIUS_DOCKER_DIR\" -i docker-compose.yml ; docker-compose up --detach --force-recreate scirius ; sleep 10s ; echo \"Waiting for container\" ; while ! docker exec -t scirius sleep 10s; do sleep 10s; done)'"
    ssh "$host" "sudo docker exec -t scirius bash -x -c 'which gcc || (apt-get --allow-releaseinfo-change update && apt-get install -y build-essential libpq-dev python3-dev libffi-dev libldap2-dev libsasl2-dev libssl-dev libz-dev virtualenv python3-virtualenv vim psmisc make)'"
    ssh "$host" "sudo docker exec -t scirius bash -x -c 'cd $SCIRIUS_DOCKER_DIR ; pip3 install --upgrade pip ; pip3 install -r requirements.txt'"
fi

if [ "$dev_ui" == "1" ]
then
    # Force nodejs 18
    NODE_PREF='Package: nodejs
Pin: origin ""
Pin-Priority: -1

Package: nodejs
Pin: version 18*
Pin-Priority: 999'
    ssh "$host" "sudo docker exec -t scirius bash -x -c 'echo \"$NODE_PREF\" > /etc/apt/preferences.d/nodejs'"

    ssh "$host" "sudo docker exec -t scirius bash -x -c 'apt-get --allow-releaseinfo-change update && apt-get install -y apt-transport-https gnupg2 &&
                    curl https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add - &&
                    echo deb\ https://deb.nodesource.com/node_18.x\ bullseye\ main > /etc/apt/sources.list.d/nodesource.list &&
                    apt-get --allow-releaseinfo-change update && apt-get install -y nodejs'"

    ssh "$host" "sudo docker exec -t scirius bash -x -c 'cd $SCIRIUS_DOCKER_DIR && npm install'"
    ssh "$host" "sudo docker exec -t scirius bash -x -c 'cd $SCIRIUS_DOCKER_DIR/ui && npm install'"
fi

if [ "$build_ui" == 1 ]
then
    ssh "$host" "sudo docker exec -t scirius bash -x -c 'cd $SCIRIUS_DOCKER_DIR/ui && set -a && source .env && set +a && npm run build && cp webpack-stats-ui.prod.json ../rules/static/'"
fi

if [ "$scirius_postsync" == 1 ]
then
    ssh "$host" "sudo docker exec -t scirius bash -x -c 'sed -e s/^DEBUG\ =.*/DEBUG\ =\ True/ -i $SCIRIUS_DOCKER_DIR/scirius/local_settings.py ; $MANAGE makemigrations; $MANAGE migrate --noinput'"
fi

if [ "$build_ui" == 1 ] || [ "$scirius_postsync" == 1 ]
then
    ssh "$host" "sudo docker exec -t scirius $MANAGE collectstatic --noinput"
fi
