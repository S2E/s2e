## GTISC S2E Image Build

Run `build_image_and_push.sh` to rebuild the s2e image and push to our private docker registry. All workers will pull the latest build from the registry before each run.

Note that `build_image_and_push.sh` can be run in any repo. Since currently GTISC/s2e seems to be the only one that's frequently changing, we are only integrating the script to the CI of this repo for now.