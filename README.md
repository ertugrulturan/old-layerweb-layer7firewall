# Install
```bash
wget -qO - https://dl.xanmod.org/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
sudo apt install linux-xanmod-rt-x64v3

apt update; apt -y install wget zip unzip tar curl ca-certificates && apt install -y perl libperl-dev libgd3 libgd-dev libgeoip1 libgeoip-dev geoip-bin libxml2 libxml2-dev libxslt1.1 libxslt1-dev &&
apt-get -y install build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev libgd-dev libxml2 libxml2-dev uuid-dev &&
apt -y install curl wget build-essential checkinstall &&
apt -y install net-tools sshpass rsync sysstat bc dnsutils &&
apt -y install libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev &&
apt -y install libreadline-gplv2-dev nginx nginx-extras

docker run -d -p 80:80 -p 443:443   --restart always   -v /etc/nginx/ssl/cert.pem:/etc/nginx/cert.pem   -v /etc/nginx/ssl/key.pem:/etc/nginx/key.pem   -v /root/nginx.conf:/etc/nginx/nginx.conf nginx

echo "* - nofile 65536" >> /etc/security/limits.conf
echo "root - nofile 65536" >> /etc/security/limits.conf
echo "DefaultLimitNOFILE=65536" >> /etc/systemd/system.conf
```
## and https://github.com/ertugrulturan/Kernel-DOS-Self-Protection
It is an experimental project, so I will not share all the installation instructions, but even this much will help the enthusiasts improve. Good works.

