package base

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"strings"

	"github.com/wsczx/remlink/pkg/utils"
	"github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xlzd/gotp"
)

var (
	// pass明文
	passwd string
	// 生成otp
	otp bool
	// 生成密钥
	secret bool
	// 显示版本信息
	rev bool
	// 输出debug信息
	debug bool
	// 重置管理员密码
	ResetAdminPassFlag bool
	// 强制禁用管理员两步验证
	DisableAdminOtpFlag bool
	// 切换 FakeDNS 可见性
	EnableFakeDNSFlag bool

	// Used for flags.
	runSrv bool

	linkViper *viper.Viper
	rootCmd   *cobra.Command
)

// Execute executes the root command.
func execute() {
	initCmd()

	err := rootCmd.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}

	if !runSrv {
		if debug {
			items := GetConfigMeta()
			fmtStr := "%-18v %-20v %v\n"
			fmt.Printf(fmtStr, "Name", "Value", "Info")
			for _, v := range items {
				fmt.Printf(fmtStr, v["name"], v["data"], v["usage"])
			}
		}
		os.Exit(0)
	}

	// 配置文件已移除，服务启动使用默认值、命令行/环境变量和数据库配置。
}

func initCmd() {
	linkViper = viper.New()
	rootCmd = &cobra.Command{
		Use:   "remlink",
		Short: "RemLink VPN Server",
		Long:  `RemLink is a VPN Server application`,
		Run: func(cmd *cobra.Command, args []string) {
			runSrv = true

			if rev {
				printVersion()
				os.Exit(0)
			}
		},
	}

	linkViper.SetEnvPrefix("link")

	// 从 ServerConfig struct tag 注册命令行参数和默认值
	registerFlagsFromConfig()

	rootCmd.Flags().BoolVarP(&rev, "version", "v", false, "display version info")
	rootCmd.Flags().BoolVarP(&ResetAdminPassFlag, "reset-admin-password", "", false, "重置管理员密码为随机密码")
	rootCmd.Flags().BoolVarP(&DisableAdminOtpFlag, "disable-admin-otp", "", false, "强制禁用管理员两步验证（OTP密钥丢失时使用）")
	rootCmd.Flags().BoolVarP(&EnableFakeDNSFlag, "enable-fakedns", "", false, "开启 FakeDNS 功能在管理界面的可见性")
	rootCmd.Flags().MarkHidden("enable-fakedns")
	rootCmd.AddCommand(initToolCmd())

	cobra.OnInitialize(func() {
		linkViper.AutomaticEnv()
	})
}

// 从 ServerConfig struct tag 中读取元数据注册 cobra flags
func registerFlagsFromConfig() {
	typ := reflect.TypeFor[ServerConfig]()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := field.Tag.Get("json")
		usage := field.Tag.Get("usage")

		switch field.Type.Kind() {
		case reflect.String:
			dv := field.Tag.Get("default")
			// AdminPass 默认值由 CompleteConfig 随机生成，不暴露在命令行
			if dv == "defaultPwd" {
				dv = ""
			}
			rootCmd.Flags().StringP(name, "", dv, usage)
		case reflect.Int:
			dv := field.Tag.Get("default")
			var iDef int
			fmt.Sscan(dv, &iDef)
			rootCmd.Flags().IntP(name, "", iDef, usage)
		case reflect.Bool:
			dv := field.Tag.Get("default")
			def := dv == "true"
			rootCmd.Flags().BoolP(name, "", def, usage)
		}

		linkViper.BindPFlag(name, rootCmd.Flags().Lookup(name))
		linkViper.BindEnv(name)
	}
}

func initToolCmd() *cobra.Command {
	toolCmd := &cobra.Command{
		Use:   "tool",
		Short: "RemLink tool",
		Long:  `RemLink tool is a application`,
	}

	toolCmd.Flags().BoolVarP(&rev, "version", "v", false, "display version info")
	toolCmd.Flags().BoolVarP(&secret, "secret", "s", false, "generate a random jwt secret")
	toolCmd.Flags().StringVarP(&passwd, "passwd", "p", "", "convert the password plaintext")
	toolCmd.Flags().BoolVarP(&otp, "otp", "o", false, "generate a random otp secret")
	toolCmd.Flags().BoolVarP(&debug, "debug", "d", false, "list the config viper.Debug() info")

	toolCmd.Run = func(cmd *cobra.Command, args []string) {
		runSrv = false

		switch {
		case rev:
			printVersion()
		case secret:
			s, _ := utils.RandSecret(40, 60)
			s = strings.Trim(s, "=")
			fmt.Printf("Secret: %s\n", s)
		case otp:
			s := gotp.RandomSecret(32)
			fmt.Printf("Otp: %s\n\n", s)
			qrstr := fmt.Sprintf("otpauth://totp/%s:%s?issuer=%s&secret=%s", "remlink_admin", "admin@remlink", "remlink_admin", s)
			qr, _ := qrcode.New(qrstr, qrcode.High)
			ss := qr.ToSmallString(false)
			io.WriteString(os.Stderr, ss)
		case passwd != "":
			pass, _ := utils.PasswordHash(passwd)
			fmt.Printf("Passwd: %s\n", pass)
		case debug:
			// linkViper.Debug()
		default:
			fmt.Println("Using [remlink tool -h] for help")
		}
	}

	return toolCmd
}

func printVersion() {
	fmt.Printf("%s v%s build on %s [%s, %s] date:%s commit_id(%s)\n",
		APP_NAME, APP_VER, runtime.Version(), runtime.GOOS, runtime.GOARCH, BuildDate, CommitId)
}
