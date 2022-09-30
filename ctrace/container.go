package ctrace

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	dockerContext "context"

	bpf "github.com/aquasecurity/libbpfgo"
	log "github.com/sirupsen/logrus"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

// Containers contain information about host running containers in the host.
type Containers struct {
	cgroupV1 bool
	cgroupMP string
	cgroups  map[uint32]CgroupInfo
	deleted  []uint64
}

type CgroupInfo struct {
	Path        string
	ContainerId string
	Runtime     string
	expiresAt   time.Time
}

// InitContainers initializes a Containers object and returns a pointer to it.
// User should further call "Populate" and iterate with Containers data.
func InitContainers() *Containers {
	cgroupV1 := false
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); os.IsNotExist(err) {
		cgroupV1 = true
	}

	return &Containers{
		cgroupV1: cgroupV1,
		cgroupMP: "",
		cgroups:  make(map[uint32]CgroupInfo),
	}
}

func (c *Containers) IsCgroupV1() bool {
	return c.cgroupV1
}

// Populate will populate all Containers information by reading mounted proc
// and cgroups filesystems.
func (c *Containers) Populate() error {
	// do all the hard work
	err := c.procMountsCgroups()
	if err != nil {
		return err
	}

	return c.populate()
}

// procMountsCgroups finds cgroups v1 and v2 mountpoints for the procfs walks.
func (c *Containers) procMountsCgroups() error {
	// find cgroups v1 and v2 mountpoints for procfs walks

	mountsFile := "/proc/mounts"
	file, err := os.Open(mountsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for i := 1; scanner.Scan(); i++ {
		sline := strings.Split(scanner.Text(), " ")
		mountpoint := sline[1]
		fstype := sline[2]
		if c.cgroupV1 {
			if fstype == "cgroup" && strings.Contains(mountpoint, "cpuset") {
				c.cgroupMP = mountpoint
			}
		} else if fstype == "cgroup2" {
			c.cgroupMP = mountpoint
		}
	}

	return nil
}

// populate walks through cgroups (v1 & v2) filesystems and
// finds directories based on known container runtimes patterns.
// it then extracts containers information and saves it by their uuid
func (c *Containers) populate() error {
	fn := func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			return nil
		}

		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			return nil
		}

		// The lower 32 bits of the cgroup id are the inode number of the matching cgroupfs entry
		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err != nil {
			return nil
		}

		_, err = c.CgroupUpdate(stat.Ino, path)
		return err
	}

	if c.cgroupMP == "" {
		return fmt.Errorf("could not determine cgroup mount point")
	}

	return filepath.WalkDir(c.cgroupMP, fn)
}

func (c *Containers) CgroupLookupUpdate(cgroupId uint64) error {

	fn := func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			return nil
		}

		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			return nil
		}

		// The lower 32 bits of the cgroup id are the inode number of the matching cgroupfs entry
		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err != nil {
			return nil
		}

		// Check if this cgroup path belongs to cgroupId
		if (stat.Ino & 0xFFFFFFFF) != (cgroupId & 0xFFFFFFFF) {
			return nil
		}

		// If we reached this point, we found a match for cgroupId - update cgroups map and break search
		c.CgroupUpdate(cgroupId, path)
		return fs.ErrExist
	}

	err := filepath.WalkDir(c.cgroupMP, fn)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err == nil {
		// No match was found - update cgroup id with an empty entry
		c.cgroups[uint32(cgroupId)] = CgroupInfo{}
	}

	return err
}

// check if path belongs to a known container runtime and
// add cgroupId with a matching container id, extracted from path
func (c *Containers) CgroupUpdate(cgroupId uint64, path string) (CgroupInfo, error) {
	info := CgroupInfo{Path: path}
	// log.Debug(cgroupId, path) //40 /sys/fs/cgroup/cpuset

	for _, pc := range strings.Split(path, "/") {
		if len(pc) < 64 {
			continue
		}
		containerId, runtime := c.getContainerIdFromCgroup(pc)
		if containerId == "" {
			continue
		}
		info.ContainerId = containerId
		info.Runtime = runtime
		// log.Debug("CgroupUpdate", path, info.ContainerId, info.Runtime)
	}

	c.cgroups[uint32(cgroupId)] = info
	return info, nil
}

// extract container id and container runtime from path
func (c *Containers) getContainerIdFromCgroup(pathComponent string) (string, string) {
	runtime := "unknown"
	path := strings.TrimSuffix(pathComponent, ".scope")

	if strings.HasPrefix(path, "docker-") {
		runtime = "docker"
		path = strings.TrimPrefix(path, "docker-")
		goto check
	}
	if strings.HasPrefix(path, "crio-") {
		runtime = "crio"
		path = strings.TrimPrefix(path, "crio-")
		goto check
	}
	if strings.HasPrefix(path, "cri-containerd-") {
		runtime = "containerd"
		path = strings.TrimPrefix(path, "cri-containerd-")
		goto check
	}
	if strings.HasPrefix(path, "libpod-") {
		runtime = "podman"
		path = strings.TrimPrefix(path, "libpod-")
		goto check
	}

check:
	if matched, _ := regexp.MatchString(`^[A-Fa-f0-9]{64}$`, path); !matched {
		return "", ""
	}

	return path, runtime
}

func (c *Containers) CgroupRemove(cgroupId uint64) {
	now := time.Now()
	// prune containers that have been removed more than 5 seconds ago
	var deleted []uint64
	for _, id := range c.deleted {
		info := c.cgroups[uint32(id)]
		if now.After(info.expiresAt) {
			delete(c.cgroups, uint32(id))
		} else {
			deleted = append(deleted, id)
		}
	}
	c.deleted = deleted

	info := c.cgroups[uint32(cgroupId)]
	info.expiresAt = now.Add(5 * time.Second)
	c.cgroups[uint32(cgroupId)] = info
	// keep track of removed containers for a short period
	c.deleted = append(c.deleted, cgroupId)
}

// GetContainers provides a list of all added containers by their uuid.
func (c *Containers) GetContainers() {
	// var conts []string
	// for _, v := range c.cgroups {
	// 	if v.ContainerId != "" && v.expiresAt.IsZero() {
	// 		conts = append(conts, v.ContainerId[:12])
	// 		// fmt.Println(v.Runtime, v.expiresAt)
	// 	}
	// }
	//第一步：获取ctx
	ctx := dockerContext.Background()

	//获取cli客户端对象
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	//通过cli客户端对象去执行ContainerList(其实docker ps 不就是一个docker正在运行容器的一个list嘛)
	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})

	//下面这条命令可以获取到docker ps -a 也就是所有容器包括运行的和没有运行的
	//containers, err := cli.ContainerList(ctx, types.ContainerListOptions{All: true})
	if err != nil {
		panic(err)
	}

	//将获取到的结果输出
	w := tabwriter.NewWriter(os.Stdout, 12, 1, 3, ' ', 0)
	fmt.Fprint(w, "CONTAINER ID\tIMAGE\tCOMMAND\tCREATED\tSTATUS\tPORTS\tNAME\n")
	for _, container := range containers {
		// fmt.Printf("%s,%v", container.Created, container.Created)
		// created := time.Now().Format("2006-01-02 15:04:05")
		tm := time.Unix(container.Created, 0)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t",
			container.ID[:12],
			container.Image,
			container.Command,
			tm.Format("2006-01-02 15:04:05"),
			container.Status)
		if len(container.Ports) != 0 {
			fmt.Fprintf(w, "%v:%v->%v/%v,%v:%v->%v/%v\t",
				container.Ports[0].IP, container.Ports[0].PublicPort, container.Ports[0].PrivatePort, container.Ports[0].Type,
				container.Ports[1].IP, container.Ports[1].PublicPort, container.Ports[1].PrivatePort, container.Ports[1].Type)
		} else {
			fmt.Fprintf(w, "\t")
		}
		fmt.Fprintf(w, "%v\n", strings.TrimLeft(container.Names[0], "/"))
	}
	w.Flush()
	// return conts
}

func (c *Containers) GetCgroupInfo(cgroupId uint64) CgroupInfo {
	return c.cgroups[uint32(cgroupId)]
}

func (c *Containers) CgroupExists(cgroupId uint64) bool {
	if _, ok := c.cgroups[uint32(cgroupId)]; ok {
		return true
	}
	return false
}

const (
	containerExisted uint8 = iota + 1
	containerCreated
	containerStarted
)

func (c *Containers) PopulateContainersBpfMap(bpfModule *bpf.Module) error {
	containersMap, err := bpfModule.GetMap("existed_containers_map")
	if err != nil {
		return err
	}

	for cgroupIdLsb, info := range c.cgroups {
		if info.ContainerId != "" {
			state := containerExisted
			// 容器cgroupIdLsb的状态state
			err = containersMap.Update(cgroupIdLsb, state)
			log.Debug("cgroupIdLsb:", cgroupIdLsb)
		}
	}

	return err
}

func (c *Containers) RemoveFromContainersBpfMap(bpfModule *bpf.Module, cgroupId uint64) error {
	containersMap, err := bpfModule.GetMap("existed_containers_map")
	if err != nil {
		return err
	}

	cgroupIdLsb := uint32(cgroupId)
	return containersMap.DeleteKey(cgroupIdLsb)
}
