if [[ -z "${DOCKER_REGISTRY_USER}" ]]; then
  echo "Error: Please set DOCKER_REGISTRY_USER."
  exit 1
fi

if [[ -z "${DOCKER_REGISTRY_PASS}" ]]; then
  echo "Error: Please set DOCKER_REGISTRY_PASS."
  exit 1
fi

if [ -z "${TARGET_BRANCH}" ]; then 
    TARGET_BRANCH='master'
    echo "TARGET_BRANCH not set. Defaulting to master."
else 
    echo "TARGET_BRANCH set to ${TARGET_BRANCH}"
fi

cd "$(dirname "$0")"
docker build --no-cache --build-arg TARGET_BRANCH=$TARGET_BRANCH -t super.gtisc.gatech.edu/s2e:$TARGET_BRANCH .

docker login super.gtisc.gatech.edu --username=$DOCKER_REGISTRY_USER --password=$DOCKER_REGISTRY_PASS
docker push super.gtisc.gatech.edu/s2e:$TARGET_BRANCH
docker logout super.gtisc.gatech.edu