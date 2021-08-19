# An eBPF Load Balancer from scratch

As seen at [eBPF Summit 2021](https://ebpf.io/summit-2021). This is not production ready :-) 

This uses `libbpf` as a git submodule. If you clone this repo you'll need to run
`git submodule init` and `git submodule update` to get your copy of that repo. 

## Load Balancer container

In my demo I'm running all the components as containers. For the Load Balancer
component itself I created an image locally by running
an `ubuntu` container and adding dependencies so that it can compile the eBPF code: 

```bash
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential make
```

Save this image off with `docker commit <running container> ubuntu-working`.
Running it as privileged gives it permissions to load eBPF programs: 

```bash
docker run --rm -it -v ~/lb-from-scratch:/lb-from-scratch --privileged -h lb --name lb --env TERM=xterm-color ubuntu-working
```

Exec into that container, `cd lb-from-scratch` and then `make` should build and
install the load balancer onto the eth0 interface for that container. 

## Demo containers

Here's how I started the containers for the two backends and the client: 

```bash
docker run -d --rm --name backend-A -h backend-A --env TERM=xterm-color nginxdemos/hello:plain-text
docker run -d --rm --name backend-B -h backend-B --env TERM=xterm-color nginxdemos/hello:plain-text
docker run --rm -it -h client --name client --env TERM=xterm-color ubuntu
```

Exec into one of the backends and install tcpdump with `apk add tcpdump` if you want to see incoming
traffic there.

Run something on the host that tails the output from BPF trace (for example, my [hello
world eBPF beginners examples](https://github.com/lizrice/libbpfgo-beginners))

## IP addresses

The IP addresses for the client, load balancer and two backends are hard-coded at the top of the .c file. You'll likely need to change these to match the addresses assigned to the containers you run.
