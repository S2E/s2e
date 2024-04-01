if [[ -z "${DOCKER_REGISTRY_USER}" ]]; then
  echo "Error: Please set DOCKER_REGISTRY_USER."
  exit 1
fi

if [[ -z "${DOCKER_REGISTRY_PASS}" ]]; then
  echo "Error: Please set DOCKER_REGISTRY_PASS."
  exit 1
fi

cd "$(dirname "$0")"
docker build --no-cache -t super.gtisc.gatech.edu/s2e:latest .

docker login super.gtisc.gatech.edu --username=$DOCKER_REGISTRY_USER --password=$DOCKER_REGISTRY_PASS
docker push super.gtisc.gatech.edu/s2e:latest
docker logout super.gtisc.gatech.edu