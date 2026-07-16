.PHONY: all web build docker local run test clean

VERSION := $(shell cat version)

## 构建前端（Docker node:16-alpine）
web:
	bash scripts/build_web.sh

## 构建二进制发布包（需先执行 make web）
build: web
	bash scripts/build_docker.sh

## 构建 Docker 镜像
docker:
	bash scripts/build_docker.sh

## 推送阿里云镜像仓库
docker-cn:
	bash scripts/build_docker.sh cn

## 本地编译二进制（musl 静态链接 + UPX）
local:
	bash scripts/build_local.sh

## 编译并运行（需先 make web）
run:
	cd server && sudo go run main.go; exit 0

## 运行测试
test:
	cd server && go test ./...

## 构建 Go 后端（不依赖 Docker，需先 make web）
go:
	cd server && go build -o remlink -trimpath

## 清理构建产物
clean:
	rm -rf server/ui web/ui server/remlink remlink-deploy remlink-deploy-* artifact-dist

## 查看帮助
help:
	@echo "RemLink 构建命令:"
	@echo ""
	@echo "  make web        构建前端"
	@echo "  make build      构建前端 + Docker 镜像 + 发布包"
	@echo "  make docker     构建 Docker 镜像"
	@echo "  make docker-cn  推送阿里云镜像仓库"
	@echo "  make local      本地编译二进制（musl + UPX）"
	@echo "  make go         快速编译 Go 后端（需先 make web）"
	@echo "  make run        编译并运行"
	@echo "  make test       运行测试"
	@echo "  make clean      清理构建产物"
	@echo "  make help       显示帮助"
	@echo ""
	@echo "当前版本: $(VERSION)"

all: build
