package base

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

const (
	procModulesPath = "/proc/modules"
	inContainerKey  = "REMLINK_IN_CONTAINER"
	tunPath         = "/dev/net/tun"
)

var (
	InContainer = false
	modMap      = map[string]struct{}{}
)

func initMod() {
	container := os.Getenv(inContainerKey)
	if container == "on" {
		InContainer = true
	}
	Debug("InContainer", InContainer)
	file, err := os.Open(procModulesPath)
	if err != nil {
		err = fmt.Errorf("[ERROR] Problem with open file: %s", err)
		panic(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		splited := strings.Split(scanner.Text(), " ")
		if len(splited[0]) > 0 {
			modMap[splited[0]] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		panic(fmt.Errorf("[ERROR] 读取 %s 失败: %s", procModulesPath, err))
	}
}

func CheckModOrLoad(mod string) {
	Debug("CheckModOrLoad", mod)

	if _, ok := modMap[mod]; ok {
		return
	}

	var err error

	if mod == "tun" || mod == "tap" {
		_, err = os.Stat(tunPath)
		if err == nil {
			return
		}
	}

	if InContainer {
		log.Printf("[error] Linux module %s is not loaded, please run `modprobe %s`", mod, mod)
		return
	}

	b, err := exec.Command("modprobe", mod).CombinedOutput()
	if err != nil {
		log.Printf("modprobe %s: %s", mod, string(b))
		panic(err)
	}
}
