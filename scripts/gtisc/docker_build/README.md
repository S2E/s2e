## GTISC S2E Image Build

Run `build_image_and_push.sh` to rebuild the s2e image and push to our private docker registry. All workers will pull the latest build from the registry before each run.

Note that `build_image_and_push.sh` can be run in any repo. Since currently GTISC/s2e seems to be the only one that's frequently changing, we are only integrating the script to the CI of this repo for now.

## Workflow

```bash
# make changes in your branch and push your branch to remote
git add xxx
git commit xxx
git branch -b <YOUR BRANCH>
git push origin <YOUR BRANCH>

# build the remote branch and push it to the private registry
export DOCKER_REGISTRY_USER=xxx DOCKER_REGISTRY_PASS=yyy
TARGET_BRANCH=<YOUR BRANCH> bash ./build_image_and_push.sh

# run the pipeline against the newly pushed image
TARGET_BRANCH=<YOUR BRANCH> python3 ~/Mal-S2E/script/run_pipeline_with_docker.py xxx yyy
```


TODO: clean the built images as they will use disk space.
