#!/bin/bash

# Variables
IMAGE_NAME=rp-iam-service
TAG=v0.1.0
LOCAL_REPO=localhost:5000

# Build the Docker image
docker build -t $IMAGE_NAME:$TAG .

# Push the image to the local repository
docker push $LOCAL_REPO/$IMAGE_NAME:$TAG