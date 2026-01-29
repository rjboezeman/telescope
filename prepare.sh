#!/bin/bash
sudo dnf install -y epel-release
sudo dnf install -y golang
mkdir -p $HOME/go/{bin,src,pkg}
echo '# Add this to your env'
echo 'export GOPATH=$HOME/go' 
echo 'export PATH=$PATH:$GOPATH/bin'
