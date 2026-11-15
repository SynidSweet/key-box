ls -l /dev/kvm; id; docker version --format '{{.Server.Version}}'; df -h $HOME/.cache | tail -1; nproc; free -g | head -2
docker pull alpine:3.22 2>&1 | tail -3; docker image inspect alpine:3.22 --format '{{index .RepoDigests 0}}'
curl -fsSL https://cloud-images.ubuntu.com/noble/current/SHA256SUMS | grep -E 'noble-server-cloudimg-amd64.img$'
