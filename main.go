package main

import (
    "encoding/binary"
    "fmt"
    "os"
    "os/signal"
    "strconv"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

const (
    BPF_OBJ_PATH = "drop_packets.o"
    PORT_MAP_KEY = 0
)

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: sudo go run main.go <port>")
        return
    }

    port, err := strconv.Atoi(os.Args[1])
    if err != nil {
        fmt.Printf("Invalid port: %v\n", err)
        return
    }

    if err := rlimit.RemoveMemlock(); err != nil {
        fmt.Printf("Failed to remove memlock limit: %v\n", err)
        return
    }

    spec, err := ebpf.LoadCollectionSpec(BPF_OBJ_PATH)
    if err != nil {
        fmt.Printf("Failed to load eBPF object: %v\n", err)
        return
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        fmt.Printf("Failed to create eBPF collection: %v\n", err)
        return
    }
    defer coll.Close()

    portMap := coll.Maps["port_map"]
    if portMap == nil {
        fmt.Println("Failed to get port_map")
        return
    }

    portVal := make([]byte, 2)
    binary.LittleEndian.PutUint16(portVal, uint16(port))
    if err := portMap.Update(PORT_MAP_KEY, portVal, ebpf.UpdateAny); err != nil {
        fmt.Printf("Failed to update port map: %v\n", err)
        return
    }
    fmt.Printf("Port set to %d\n", port)

    link, err := link.AttachXDP(link.XDPOptions{
        Program:   coll.Programs["drop_tcp_packets"],
        Interface: 0, // Change to the correct interface index
    })
    if err != nil {
        fmt.Printf("Failed to attach XDP program: %v\n", err)
        return
    }
    defer link.Close()

    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    <-sigs
    fmt.Println("Exiting...")
}
