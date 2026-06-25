# Copyright The Ratify Authors.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.245.2/containers/go/.devcontainer/base.Dockerfile

# [Choice] Go version (use -bullseye variants on local arm64/Apple Silicon): 1.22-bullseye, 1.21-bullseye, 1, 1.19, 1.18, 1-bullseye, 1.19-bullseye, 1.18-bullseye, 1-buster, 1.19-buster, 1.18-buster
FROM mcr.microsoft.com/vscode/devcontainers/go:1.22-bullseye@sha256:f2d2a2bf200bb2de430a9eb4115fa87ae5d665a39539a2d5dee868227f786531

# [Choice] Node.js version: none, lts/*, 18, 16, 14
ARG NODE_VERSION="none"
RUN if [ "${NODE_VERSION}" != "none" ]; then su vscode -c "umask 0002 && . /usr/local/share/nvm/nvm.sh && nvm install ${NODE_VERSION} 2>&1"; fi

ARG KIND_VERSION="0.17.0"
RUN curl -Lo /usr/local/bin/kind https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-amd64 \
  && chmod +x /usr/local/bin/kind

ARG BATS_VERSION="1.8.2"
RUN curl -Lo bats.tar.gz https://github.com/bats-core/bats-core/archive/v${BATS_VERSION}.tar.gz \
  && tar -zxf bats.tar.gz \
  && bash ./bats-core-${BATS_VERSION}/install.sh /usr/local \
  && rm -rf bats.tar.gz ./bats-core-${BATS_VERSION}

ARG NOTATION_VERSION="1.2.0"
RUN curl -Lo notation.tar.gz https://github.com/notaryproject/notation/releases/download/v${NOTATION_VERSION}/notation_${NOTATION_VERSION}_linux_amd64.tar.gz \
  && tar -zxf notation.tar.gz \
  && mv ./notation /usr/local/bin/notation \
  && rm -rf ./notation.tar.gz

ARG ORAS_VERSION="0.16.0"
RUN curl -Lo oras.tar.gz https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz \
  && mkdir -p oras-install \
  && tar -zxf oras.tar.gz -C oras-install \
  && mv oras-install/oras /usr/local/bin/ \
  && rm -rf ./oras-install oras.tar.gz

ARG KUBEBUILDER_VERSION="3.8.0"
RUN curl -L https://github.com/kubernetes-sigs/kubebuilder/releases/download/v${KUBEBUILDER_VERSION}/kubebuilder_linux_amd64 -o /usr/local/bin/kubebuilder \
  && chmod +x /usr/local/bin/kubebuilder

# [Optional] Uncomment this section to install additional OS packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
  && apt-get -y install --no-install-recommends protobuf-compiler libprotobuf-dev

# [Optional] Uncomment the next lines to use go get to install anything else you need
USER vscode
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.1 \
  && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0 \
  && chmod a+w -R /go/pkg

# [Optional] Uncomment this line to install global node packages.
# RUN su vscode -c "source /usr/local/share/nvm/nvm.sh && npm install -g <your-package-here>" 2>&1
