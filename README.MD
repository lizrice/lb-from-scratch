# Network-related demos

* Load Balancer from Scratch 
* Packetdrop 
* Packet counting

## An eBPF Load Balancer from scratch

As seen at [eBPF Summit 2021](https://ebpf.io/summit-2021). This is not production ready :-) 

This uses `libbpf` as a git submodule. If you clone this repo you'll need to run
`git submodule init` and `git submodule update` to get your copy of that repo. 

## Load Balancer container

In my demo I'm running all the components as containers. 

For the Load Balancer component itself you can build a Docker image from Dockerfile.lb, which starts from 
an `ubuntu` container with additional dependencies so that it can compile the eBPF code. 

```
docker buildx create --name mybuilder --bootstrap --use
docker buildx build --push --platform linux/arm64,linux/amd64 --tag lizrice/ubuntu-ebpf-lb -f Dockerfile.lb .
```

```bash
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential make linux-tools-common
```

*Note: gcc-multilib is not currently available for ARM architectures on Ubuntu 22.04. I'm adding `/usr/include/$(shell uname -m)-linux-gnu` into the include path instead. See [this thread for more info](https://patchwork.ozlabs.org/project/netdev/patch/20200311123421.3634-1-tklauser@distanz.ch/).*

My version of this container image is available at `lizrice/ubuntu-ebpf-lb`.

Running it as privileged gives it permissions to load eBPF programs: 

```bash
docker run --rm -it -v ~/lb-from-scratch:/lb-from-scratch --privileged -h lb --name lb --env TERM=xterm-color lizrice/ubuntu-ebpf-lb
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
or just `sudo cat /sys/kernel/debug/tracing/trace_pipe`

### IP addresses

The IP addresses for the client, load balancer and two backends are hard-coded at the top of the .c file. You'll likely need to change these to match the addresses assigned to the containers you run.


## Packet drop - ping demo 

Install ping utils into the ubuntu-working container 

```bash
apt install iputils-ping
```
Save off into an image called ubuntu-pingbox: `docker commit <running container> ubuntu-pingbox`

```bash
docker run --rm -it -v ~/ebpf-net-beginners:/ebpf-net-beginners --privileged -h pingbox --name pingbox --env TERM=xterm-color ubuntu-pingbox
```

Find its ip address (`ip a` from inside, or `docker inspect pingbox`)

Check you can ping it from outside.

```bash
cd ebpf-net-beginners
```

Comment in the `packetdrop` target in the Makefile and then `make` to load the
program. Edit and make to drop or pass ICMP packets. 

Tracing:  `cat /sys/kernel/debug/tracing/trace_pipe` on host

Listen with `nc -l 80`
Curl from host with `curl -v 172.17.0.2` (use verbose to see the response even
if it's not valid HTML) 

## xdp_liz

Counts packets! 
