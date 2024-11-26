package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/xuri/excelize/v2"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ##########################W##################### 入口 ###################################################################
func main() {
	// 记录开始时间
	startTime := time.Now()
	filename := GetParameter()
	if filename == "" {
		return
	}
	fmt.Println("本检测工具原创者为：白音\n为了当前主机稳定，同一时间最多在线 50 台检测\n启动后会自动检测并生成 linux_baseline_resoult 文件夹\n检测后的结果都在linux_baseline_resoult文件夹中\n连接失败的主机会写入到当前目录的fail.txt文件中")
	if err := ensureDirectoryExists("./linux_baseline_resoult"); err != nil {
		fmt.Println(err)
	}
	// 读取hosts.txt文件
	hosts, err := readHostsFromFile(filename)
	errPrint("读取文件错误", err)

	// ssh连接主机
	GetSsh(hosts)

	endTime := time.Now()
	elapsedTime := endTime.Sub(startTime)
	fmt.Printf("程序执行时间: %v\n", elapsedTime)
}

// ############################################### 以下是主方法中包装的小函数 ###################################################################

func GetParameter() string {
	// 定义一个字符串类型的标志，用于接收文件名
	fileName := flag.String("file", "", "文件名")
	flag.Parse()

	// 检查是否指定了文件名
	if *fileName == "" {
		log.Fatal("文件格式\n必须指定文件名，使用 -file 文件名")
	} else if *fileName == "" && flag.NFlag() == 0 {
		log.Fatal(`
	linux基线检测脚本ssh远程登录版
	为了系统稳定性最高支持50个同时检测
	平均一台主机检测时间为1.2秒以内
	使用方式：
	chmod +x linux-script-ssh
	./linux-script-ssh -file=hosts.txt
	文件格式为ip,username,passwd,port
	注意使用英文逗号分割
	port 不指定默认为22
	`)
		return ""
	}
	return *fileName
}

// 从文件中读取主机信息
func readHostsFromFile(filename string) ([]HostInfo, error) {
	var hosts []HostInfo
	file, err := os.Open(filename)
	if err != nil {
		return hosts, err
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "\n" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) == 4 {
			host := parts[0]
			username := parts[1]
			password := parts[2]
			port, err := strconv.Atoi(parts[3])
			if err != nil {
				continue // 忽略无法转换为整数的端口号
			}

			hosts = append(hosts, HostInfo{
				Host:     host,
				User:     username,
				Password: password,
				Port:     port,
			})
		} else if len(parts) == 5 {
			host := parts[0]
			username := parts[1]
			password := parts[2]
			port, err := strconv.Atoi(parts[3])
			if err != nil {
				continue // 忽略无法转换为整数的端口号
			}

			hosts = append(hosts, HostInfo{
				User:     username,
				Password: password,
				Host:     host,
				Port:     port,
				Root:     parts[4],
			})
		} else if len(parts) == 3 {
			host := parts[0]
			username := parts[1]
			password := parts[2]
			hosts = append(hosts, HostInfo{
				User:     username,
				Password: password,
				Host:     host,
				Port:     22,
			})
		} else {
			continue // 忽略无法解析的行
		}

	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return hosts, nil
}

type HostInfo struct {
	User     string
	Password string
	Host     string
	Port     int
	Root     string
}

func GetSsh(hosts []HostInfo) {
	executeSSHCommand := func(host HostInfo) (string, [][]string, [][]interface{}, string) {
		fmt.Printf("开始连接：%s\n", host.Host)
		config := &ssh.ClientConfig{
			User: host.User,
			Auth: []ssh.AuthMethod{
				ssh.Password(host.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 注意：这在生产环境中是不安全的
		}

		conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host.Host, host.Port), config)
		if err != nil {
			fmt.Printf("ssh连接失败，主机为：%s,错误信息：%s  |||\n", host.Host, err)
			return "", nil, nil, fmt.Sprintf("%s 主机ssh连接失败", host.Host)
		}
		defer conn.Close()

		return ScanLinuxSsh(conn, host.Host)
	}
	maxConcurrent := 50 // 控制最大同时运行的会话数量
	var wg sync.WaitGroup
	results := make(chan string, len(hosts))
	sem := make(chan struct{}, maxConcurrent)
	var failLine []string
	for _, host := range hosts {
		wg.Add(1)
		go func(h HostInfo) {
			defer wg.Done()
			sem <- struct{}{}        // 获取一个许可证
			defer func() { <-sem }() // 释放许可证
			ipAddress, xlsxData, hostInfo, result := executeSSHCommand(h)
			if strings.Contains(result, "ssh连接失败") {
				results <- result
				failLine = append(failLine, result)
				return
			}
			// 最后保存Excel
			err := saveExcel("./linux_baseline_resoult/"+ipAddress+".xlsx", xlsxData, hostInfo)
			errPrint("保存xlsx文件错误", err)
			results <- result
		}(host)
	}
	fmt.Println("等待所有任务完成...")
	go func() {
		wg.Wait()
		close(results)
	}()
	if failLine != nil {
		fmt.Println("已将连接失败主机保存至当前目录failtxt")
		if err := saveTxt(failLine); err != nil {
			fmt.Println("保存连接失败的主机失败，错误：", err)
		}
	} else {
		fmt.Println("恭喜无连接失败主机")
	}
	for result := range results {
		fmt.Println(result)
	}
}

func saveTxt(failLine []string) error {
	_, err := os.Stat("fail.txt")
	if err != nil {
		file, err := os.Create("fail.txt")
		if err != nil {
			return err // 如果文件无法创建或打开，程序终止
		}
		defer file.Close()

		// 创建一个带缓冲的写入器
		writer := bufio.NewWriter(file)
		// 写入数据
		for _, line := range failLine {
			_, err = writer.WriteString(line + "\n") // 每个字符串后加上换行符
			if err != nil {
				return err
			}
		}

		// 刷新缓冲区以确保所有数据都被写入到文件
		err = writer.Flush()
		if err != nil {
			return err
		}
	}
	return nil
}

func ensureDirectoryExists(dirPath string) error {
	// 检查文件夹是否存在
	info, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件夹不存在，创建文件夹
			if err = os.MkdirAll(dirPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dirPath, err)
			}
			return nil
		}
		return fmt.Errorf("error checking directory %s: %w", dirPath, err)
	}

	// 检查 info 是否表示一个目录
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dirPath)
	}

	return nil
}

// 获取系统
func Get_Os(conn *ssh.Client) (string, string, string, string, string) {
	var bashrc, authSetPath, accountSetPath, passwordComplexity string
	// 定义列表
	var debianLike = []string{"debian", "ubuntu", "Linux Mint", "elementary OS",
		"Debian GNU/Linux", "Ubuntu", "Kali GNU/Linux", "Kylin"}

	var redhatLike = []string{"CentOS Linux", "Red Hat Enterprise Linux", "Red Hat Enterprise Linux Server",
		"Fedora", "Anolis OS", "openEuler", "Oracle Linux Server", "Kylin Linux Advanced Server",
		"Alibaba Cloud Linux", "Alibaba Cloud Linux (Aliyun Linux)"}

	var archLike = []string{"Arch Linux"}

	var suseLike = []string{"openSUSE Leap", "SUSE Linux Enterprise Server"}
	// 获取本地 os-release 中的 name
	localSys, osName := getLocalSys(conn)
	localSys = strings.Replace(localSys, "\"", "", -1)
	localSys = strings.Replace(localSys, "    ", "", -1)
	localSys = strings.Replace(localSys, "\n", "", -1)
	localSys = strings.Replace(localSys, "\t", "", -1)
	localSys = strings.Replace(localSys, "\r", "", -1)
	localSys = strings.Replace(localSys, "\f", "", -1)
	//fmt.Println("local_sys = " + localSys)

	// 初始化操作系统类型变量
	var osLike string

	// 判断发行版属于哪个列表
	if contains(debianLike, localSys) {
		osLike = "debian_like"
	} else if contains(redhatLike, localSys) {
		osLike = "redhat_like"
	} else if contains(archLike, localSys) {
		osLike = "arch_like"
	} else if contains(suseLike, localSys) {
		osLike = "suse_like"
	}
	switch osLike {
	case "debian_like":
		bashrc = "/etc/bash.bashrc"
		authSetPath = "/etc/pam.d/common-auth"
		accountSetPath = "/etc/pam.d/common-account"
		passwordComplexity = "/etc/pam.d/common-password"
	case "redhat_like", "arch_like":
		bashrc = "/etc/bashrc"
		authSetPath = "/etc/pam.d/system-auth"
		accountSetPath = "/etc/pam.d/system-auth"
		passwordComplexity = "/etc/pam.d/system-auth"
	case "suse_like":
		// 在此处执行 SUSE 系操作
		bashrc = "/etc/bash.bashrc"
		authSetPath = "/etc/pam.d/common-auth"
		accountSetPath = "/etc/pam.d/common-account"
		passwordComplexity = "/etc/pam.d/common-password"
	default:
		// 如果未匹配到任何操作系统类型，可以在此添加默认操作
		fmt.Println("操作系统未识别")
	}
	return osName, bashrc, authSetPath, accountSetPath, passwordComplexity
}

// 部分异常处理
func errPrint(describe string, err error) {
	if err != nil {
		fmt.Printf("%s  :  %s", describe, err)
	}
}

// 最后保存检测结果
func saveExcel(filePath string, data [][]string, additionalData [][]interface{}) error {
	saveErr := 0
	fmt.Println("开始写入xlsx表格数据...")
	// 创建一个新的 Excel 文件
	f := excelize.NewFile()

	// 创建一个新的工作表或选择一个现有的工作表
	index, _ := f.NewSheet("Sheet1")
	SheetName := f.GetSheetName(index)
	if err := f.SetSheetName(SheetName, "基线检查"); err != nil {
		fmt.Println("创建工作表失败：", err)
	}
	NewSheetName := f.GetSheetName(index)
	// 将数据写入工作表
	for rowsIndex, rows := range data {

		for rowindex, row := range rows {
			cellAddress, _ := excelize.CoordinatesToCellName(rowindex+1, rowsIndex+1)
			if cellAddress == "" {
				continue
			}
			if err := f.SetCellValue(NewSheetName, cellAddress, row); err != nil {
				fmt.Printf("xlsx表格数据写入失败: %v\n", err)
				saveErr++
			}
		}
	}

	// 设置冻结窗格
	panesJSON := `{"freeze":true,"split":false,"x_split":0,"y_split":1,"top_left_cell":"A2","active_pane":"bottomLeft"}`
	var panes struct {
		Freeze      bool   `json:"freeze"`
		Split       bool   `json:"split"`
		XSplit      int    `json:"x_split"`
		YSplit      int    `json:"y_split"`
		TopLeftCell string `json:"top_left_cell"`
		ActivePane  string `json:"active_pane"`
	}
	err := json.Unmarshal([]byte(panesJSON), &panes)
	if err != nil {
		fmt.Printf("冻结窗格出现错误: %v\n", err)
		saveErr++
	}

	err = f.SetPanes(NewSheetName, &excelize.Panes{
		Freeze:      panes.Freeze,
		Split:       panes.Split,
		XSplit:      panes.XSplit,
		YSplit:      panes.YSplit,
		TopLeftCell: panes.TopLeftCell,
		ActivePane:  panes.ActivePane,
	})
	if err != nil {
		fmt.Printf("初始化xlsx错误: %v\n", err)
		saveErr++
	}

	// 设置列宽
	columnWidths := map[string]float64{
		"A": 6.55, "B": 15.7, "C": 4.64, "D": 41, "E": 22.73,
		"F": 21.45, "G": 21.18, "H": 22.55, "I": 22.55, "J": 8.64,
	}
	for col, width := range columnWidths {
		if err = f.SetColWidth(NewSheetName, col, col, width); err != nil {
			fmt.Printf("xlsx设置列宽错误: %v\n", err)
		}
	}

	// 设置单元格对齐方式
	style, err := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			WrapText: true,
			Vertical: "top",
		},
	})
	if err != nil {
		fmt.Printf("设置单元格对齐方式错误: %v\n", err)
		saveErr++
	}
	if err = f.SetCellStyle(NewSheetName, "A1", "J"+strconv.Itoa(len(data)+1), style); err != nil {
		fmt.Printf("设置单元格对齐方式错误: %v\n", err)
		saveErr++
	}

	// 创建第二个工作表并写入额外数据
	sheetIndex, err := f.NewSheet("主机信息")
	if err != nil {
		fmt.Printf("创建第二个工作表出现错误: %v\n", err)
		saveErr++
	}
	sheetName2 := f.GetSheetName(sheetIndex)
	for rowsIndex, rows := range additionalData {
		for rowIndex, row := range rows {
			cellAddress, _ := excelize.CoordinatesToCellName(rowIndex+1, rowsIndex+1) // 获取坐标
			if err = f.SetCellValue(sheetName2, cellAddress, row); err != nil {
				fmt.Printf("xlsx表格数据写入错误: %v\n", err)
				saveErr++
			}
		}
	}

	// 保存 Excel 文件
	if err = f.SaveAs(filePath); err != nil {
		fmt.Println("保存xlsx文件失败: ", err)
		save_status(saveErr)
		return err
	}

	fmt.Printf("%s已保存\n", filePath)
	save_status(saveErr)
	return nil
}

func getLocalSys(conn *ssh.Client) (string, string) {
	// 从stdout中读取文件内容
	reader := bufio.NewReader(startCommand(conn, "cat /etc/os-release"))
	var localSys string
	var osName string
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if strings.HasPrefix(line, "NAME=") {
			localSys = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
			break
		} else if strings.HasPrefix(line, "PRETTY_NAME=") {
			osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			break
		}
	}
	return localSys, osName
}

func readUser(path string, result7_6Data []string, HISTFILESIZE *int, HISTSIZE *int, conn *ssh.Client) (bool, string) {
	// 获取当前用户的信息
	HomeDir := StringTextScanner(startCommand(conn, "echo $HOME"))

	// 构建 ~/.bashrc 的完整路径
	bashrcPath := "cat " + HomeDir + "/" + path
	return checkHistoryFile(startCommand(conn, bashrcPath), result7_6Data, HISTFILESIZE, HISTSIZE), bashrcPath
}

// 匹配内容
func scantxt(line string, result7_6Data []string, HISTFILESIZE *int, HISTSIZE *int) {
	if !strings.HasPrefix(line, "#") && strings.Contains(line, "HISTFILESIZE") {
		if strings.Contains(line, "=") {
			result7_6Data = append(result7_6Data, line)
			value, err1 := strconv.Atoi(strings.Split(line, "=")[1])
			if err1 == nil {
				*HISTFILESIZE = value
			}
		}
	}
	if !strings.HasPrefix(line, "#") && strings.Contains(line, "HISTSIZE") {
		if strings.Contains(line, "=") {
			result7_6Data = append(result7_6Data, line)
			value, err1 := strconv.Atoi(strings.Split(line, "=")[1])
			if err1 == nil {
				*HISTSIZE = value
			}
		}
	}
}

func checkHistoryFile(filedata io.Reader, result7_6Data []string, HISTFILESIZE *int, HISTSIZE *int) bool {
	scanner := bufio.NewScanner(filedata)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		//fmt.Println(line)
		scantxt(line, result7_6Data, HISTFILESIZE, HISTSIZE)
	}

	if *HISTFILESIZE != 0 || *HISTSIZE != 0 {
		return true
	}
	return false
}

func checkUID0(conn *ssh.Client) []string {
	var userUID0 []string
	scanner := bufio.NewScanner(startCommand(conn, "cat /etc/passwd"))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		uid := fields[2]
		if uid == "0" {
			userUID0 = append(userUID0, fields[0])
		}
	}

	return userUID0
}

func getUsers(usernames []string, conn *ssh.Client) (bool, bool, bool) {
	var cmd string
	for _, username := range usernames {
		cmd = cmd + "getent passwd " + username + ";"
	}
	user1, user2, user3 := false, false, false

	fileText, err := ioutil.ReadAll(startCommand(conn, cmd))
	if err != nil {
		fmt.Println(err)
		return user1, user2, user3
	}
	for _, username := range usernames {
		if strings.Contains(string(fileText), username) {
			if username == "useradmin" {
				user1 = true
			}
			if username == "sysadmin" {
				user2 = true
			}
			if username == "auditor" {
				user3 = true
			}
		}
	}
	return user1, user2, user3
}

func checkUsers(conn *ssh.Client) (bool, bool, bool) {
	usernames := []string{"useradmin", "sysadmin", "auditor"}
	user1, user2, user3 := getUsers(usernames, conn)

	return user1, user2, user3
}

func checkCommand(conn *ssh.Client, command string) bool {
	outputStr := StringTextScanner(startCommand(conn, "service "+"status "+command))
	return strings.Contains(outputStr, "Active: active (running)") || strings.Contains(outputStr, "is running")
}

func checkNtpTime(conn *ssh.Client, command string) bool {
	outputStr := StringTextScanner(startCommand(conn, "systemctl "+"status "+command))
	return strings.Contains(outputStr, "Active: active (running)") || strings.Contains(outputStr, "is running")
}

func getKey(data_map map[string]string, str string) string {
	var keys []string
	for key := range data_map {
		keys = append(keys, key)
	}
	// 使用 strings.Join 连接这些键
	joinedKeys := strings.Join(keys, str)

	return joinedKeys
}

// 保存状态判断
func save_status(saveErr int) {
	if saveErr != 0 {
		fmt.Printf("写入失败结果次数为：%d\n", saveErr)
	} else {
		fmt.Println("本次写入很成功哟~")
	}
}

// 初始化
func start_scan(xlsxData *[][]string, conn *ssh.Client, hostIp string) ([][]interface{}, string, string, string, string) {

	// 获取操作系统的数据类型
	osName, bashrc, authSetPath, accountSetPath, passwordComplexity := Get_Os(conn)
	hostInfo := make([][]interface{}, 2)

	// 将数据添加到 hostInfo 中
	hostInfo[0] = []interface{}{"IP地址", hostIp}
	hostInfo[1] = []interface{}{"操作系统", osName}

	// 调用函数获取本机IP地址
	fmt.Println("当前检测主机操作系统为", osName, "，IP地址为", hostIp)
	//fmt.Println(osLike)
	//fmt.Println(bashrc)
	//fmt.Println(authSetPath)
	//fmt.Println(accountSetPath)
	//fmt.Println(passwordComplexity)

	// 设置title
	xlsxTitle := []string{
		"编号", "检查项", "级别", "检查项说明", "检查方法", "标准值", "检查语句", "修复方案",
		"检查情况", "符合性", "调整情况", "原因",
	}

	*xlsxData = append(*xlsxData, xlsxTitle)
	return hostInfo, bashrc, authSetPath, accountSetPath, passwordComplexity
}

// 获取文件权限
func getFilePermissions(conn *ssh.Client, filePath string) string {
	cmd := fmt.Sprintf("stat --format '%%a' %s", filePath)

	return strings.Replace(StringTextScanner(startCommand(conn, cmd)), "\n", "", -1)
}

// 读取命令执行结果并返回内容字符串
func StringTextScanner(stdout io.Reader) string {
	scanner := bufio.NewScanner(stdout)
	var output strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		if line == " " {
			return output.String()
		}
		output.WriteString(line + "\n")
	}
	return output.String()
}

// 循环确认value是否存在于tmp中
func contains(tmp []string, value string) bool {
	b := false
	for _, v := range tmp {
		if v == value {
			b = true
		}
	}
	return b
}

func startCommand(conn *ssh.Client, cmd string) io.Reader {
	session, err := conn.NewSession()
	if err != nil {
		fmt.Printf("session创建失败，错误信息：%s  |||\n", err)
	}
	stdout, err := session.StdoutPipe()
	NowCmd := fmt.Sprintf("sh -c '%s'", cmd)
	session.Run(NowCmd)
	//if err = session.Run(NowCmd); err != nil {
	//	fmt.Println(NowCmd)
	//	fmt.Println("Error check command:", err)
	//	return stdout
	//}
	return stdout
}

// 使用 "umask" 命令获取 umask 值
func getUmask(conn *ssh.Client) (string, error) {
	cmd := "sh -c umask"
	outputStr := StringTextScanner(startCommand(conn, cmd))
	// 去掉输出中的换行符
	return strings.TrimSpace(outputStr), nil
}

//############################################### 以下是主调用方法 ###################################################################

func ScanLinuxSsh(conn *ssh.Client, hostIp string) (string, [][]string, [][]interface{}, string) {
	// 根据操作系统类型执行相应的操作
	var xlsxData = [][]string{}
	// 初始化数据
	var countAll int
	var countSuccess int
	var countFail int
	var count_manual int

	// 初始化
	hostInfo, bashrc, authSetPath, accountSetPath, passwordComplexity := start_scan(&xlsxData, conn, hostIp)

	// 检查项：1
	account_admin(&xlsxData, &countAll, &countSuccess, &countFail, conn)

	// 检查项：2
	checkpPassword(&xlsxData, &countAll, &countSuccess, &countFail, conn, authSetPath, accountSetPath, passwordComplexity)

	// 检查项：3
	userAuth(&xlsxData, &countAll, &countSuccess, &countFail, &count_manual, conn, bashrc)

	// 检查项：4
	SshLog(&xlsxData, &countAll, &countSuccess, &countFail, conn)

	// 检查项：5
	Ftp_Telnet_Snmp(&xlsxData, &countAll, &countSuccess, &countFail, conn)

	// 检查项：6
	Openssh_Root(&xlsxData, &countAll, &countSuccess, &countFail, &count_manual, conn)

	// 检查项：7
	His_Ntp_Cad(conn, &xlsxData, &countAll, &countSuccess, &countFail, &count_manual)
	// 输出检查结果
	complianceRate := float64(countSuccess) / float64(countAll) * 100
	return hostIp, xlsxData, hostInfo, fmt.Sprintf("主机：%s  成功检查项共计 %d 项，合规 %d 项，不合规 %d 项，人工判断 %d 项，合规率 %d %s \n", hostIp, countAll, countSuccess, countFail, count_manual, int(complianceRate), "%")

}

// 1:帐号管理
func account_admin(xlsxData *[][]string, countAll *int, countSuccess *int, countFail *int, conn *ssh.Client) {

	// 1.1:检查是否设置除root之外UID为0的用户
	*countAll++
	var result1_1 string
	userUID0 := checkUID0(conn)
	if len(userUID0) > 1 {
		result1_1 = "不合规"
		*countFail++
		//fmt.Println("1.1:检查是否设置除root之外UID为0的用户\t", result1_1, "\t", userUID0)
	} else {
		result1_1 = "合规"
		*countSuccess++
		//fmt.Println("1.1:检查是否设置除root之外UID为0的用户\t", result1_1, "\t", userUID0)
	}
	recommendation1_1 := `1、执行备份
		cp –p /etc/passwd /etc/passwd.bak
		cp –p /etc/shadow /etc/shadow.bak
		cp –p /etc/group /etc/group.bak
		2、删除除root外其他UID为0的用户(删除之前应确保用户未被其他业务使用)或修改账号UID
		userdel {用户名}
		usermod -u {UID} {用户名}
`
	data1_1 := []string{
		"1.1",
		"检查是否设置除root之外UID为0的用户",
		"中危",
		"任何UID为0的帐户都具有系统上的超级用户特权,只有root账号的uid才能为0",
		"检查/etc/passwd，以\":\"分隔，第一项为用户名，第三项为UID",
		"不允许存在除root外UID为0的用户",
		"cat /etc/passwd | awk -F: '$3 == 0 {print $1}'",
		recommendation1_1,
		"当前具备UID权限为0的用户有：" + strings.Join(userUID0, " ; "),
		result1_1,
		"/",
		"/",
	}

	*xlsxData = append(*xlsxData, data1_1)

	// 1.2:检查是否设置系统管理员、安全保密管理员或用户管理员、安全审计员或审计操作员账户
	*countAll++
	var result1_2 string
	user1, user2, user3 := checkUsers(conn)
	if user1 && user2 && user3 {
		*countSuccess++
		result1_2 = "合规"
		//fmt.Println("1.2:检查是否设置系统管理员、安全保密管理员或用户管理员、安全审计员或审计操作员账户\t", result1_2)
	} else {
		*countFail++
		result1_2 = "不合规"
		//fmt.Println("1.2:检查是否设置系统管理员、安全保密管理员或用户管理员、安全审计员或审计操作员账户\t", result1_2)
	}
	var result1_2_data []string
	resList := []bool{user1, user2, user3}
	userList := []string{"sysadmin", "useradmin", "auditor"}
	for resIndex, row := range resList {
		if !row {
			result1_2_data = append(result1_2_data, userList[resIndex]+"\n")
		}
	}
	data1_2 := []string{
		"1.2",
		"检查是否设置系统管理员、安全保密管理员或用户管理员、安全审计员或审计操作员账户",
		"中危",
		"应分别设置系统管理员、安全保密管理员或用户管理员、安全审计员或审计操作员账户",
		"检查 /etc/passwd 是否包含sysadmin、useradmin、auditor用户",
		"同时存在sysadmin、useradmin、auditor用户",
		"grep -e sysadmin -e useradmin -e auditor /etc/passwd",
		"1、按要求创建账户\nuseradd {用户名}\n2、为用户创建密码\n passwd {用户名}",
		"当前缺少的用户账户：" + strings.Join(result1_2_data, " ; "),
		result1_2,
		"/",
		"/",
	}
	*xlsxData = append(*xlsxData, data1_2)
}

// 2.0密码复杂度检查
func checkpPassword(xlsxData *[][]string, countAll *int, countSuccess *int, countFail *int, conn *ssh.Client, authSetPath string, accountSetPath string, passwordComplexity string) {

	var flag1, flag2, flag3, flag4 bool
	// 2.1:检查设备密码复杂度策略
	*countAll++
	parsePWQualityConfig := func(content string, dcredit *string, ucredit *string, ocredit *string, lcredit *string, minclass *string, minlen *string) {
		for _, line := range strings.Split(content, "\n") {
			if strings.Contains(line, "password") && strings.Contains(line, "requisite") && (strings.Contains(line, "pam_pwquality.so") || strings.Contains(line, "pam_cracklib.so")) {
				for _, part := range strings.Fields(line) {
					switch {
					case strings.HasPrefix(part, "dcredit="):
						*dcredit = part[len("dcredit="):]
					case strings.HasPrefix(part, "ucredit="):
						*ucredit = part[len("ucredit="):]
					case strings.HasPrefix(part, "ocredit="):
						*ocredit = part[len("ocredit="):]
					case strings.HasPrefix(part, "lcredit="):
						*lcredit = part[len("lcredit="):]
					case strings.HasPrefix(part, "minclass="):
						*minclass = part[len("minclass="):]
					case strings.HasPrefix(part, "minlen="):
						*minlen = part[len("minlen="):]
					}
				}
			}
		}
	}

	dcredit, ucredit, ocredit, lcredit, minclass, minlen := "配置不存在", "配置不存在", "配置不存在", "配置不存在", "配置不存在", "配置不存在"

	passwordContent := StringTextScanner(startCommand(conn, "cat "+passwordComplexity))
	parsePWQualityConfig(passwordContent, &dcredit, &ucredit, &ocredit, &lcredit, &minclass, &minlen)

	flag1 = true
	if !(ucredit != "0" && lcredit != "0" && dcredit != "0" && ocredit != "0") || minclass != "4" {
		flag1 = false
	}

	flag2 = true
	num, _ := strconv.Atoi(minlen)
	if num < 8 {
		flag2 = false
	}

	result2_1 := "部分合规"
	if flag1 && flag2 {
		result2_1 = "合规"
		*countSuccess++
	} else if !flag1 && !flag2 {
		result2_1 = "不合规"
		*countFail++
	} else {
		*countFail++
	}
	data2_1 := []string{
		"2.1", "检查设备密码复杂度策略", "高危", "密码复杂度过低会增加密码被爆破风险。",
		fmt.Sprintf("检查%s或/etc/security/pwquality.conf中ucredit/lcredit/dcredit/ocredit/minlen/minclass的值是否符合标准值", passwordComplexity),
		"按照企业密码管理要求与等级保护标准，密码至少8位，复杂度应包含特殊字符、大小写字母和数字。",
		fmt.Sprintf("cat %s | grep -v '#' | grep password\ncat /etc/security/pwquality.conf", passwordComplexity),
		fmt.Sprintf("在%s中修改或追加ucredit/lcredit/dcredit/ocredit=-1", passwordComplexity),
		fmt.Sprintf("dcredit %s\nucredit %s\nocredit %s\nlcredit %s\nminclass %s\nminlen %s", dcredit, ucredit, ocredit, lcredit, minclass, minlen),
		result2_1, "/", "/",
	}
	*xlsxData = append(*xlsxData, data2_1)
	//fmt.Printf("2.1:检查设备密码复杂度策略\t%s\n", result2_1)

	// 2.2:检查 /etc/login.defs 中的口令策略
	*countAll++
	PASS_MIN_DAYS := "/"
	PASS_WARN_AGE := "/"
	PASS_MAX_DAYS := "/"
	PASS_MIN_LEN := "/"
	var result2_2 string
	loginDefsContent := StringTextScanner(startCommand(conn, "cat /etc/login.defs"))
	for _, line := range strings.Split(loginDefsContent, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") && strings.Contains(line, "PASS_MIN_DAYS") {
			PASS_MIN_DAYS = strings.Fields(line)[len(strings.Fields(line))-1]
		} else if !strings.HasPrefix(line, "#") && strings.Contains(line, "PASS_WARN_AGE") {
			PASS_WARN_AGE = strings.Fields(line)[len(strings.Fields(line))-1]
		} else if !strings.HasPrefix(line, "#") && strings.Contains(line, "PASS_MAX_DAYS") {
			PASS_MAX_DAYS = strings.Fields(line)[len(strings.Fields(line))-1]
		} else if !strings.HasPrefix(line, "#") && strings.Contains(line, "PASS_MIN_LEN") {
			PASS_MIN_LEN = strings.Fields(line)[len(strings.Fields(line))-1]
		}
	}

	recommendation2_2 := make([]string, 0)
	num, _ = strconv.Atoi(PASS_MIN_LEN)
	if PASS_MIN_DAYS != "/" && num >= 7 {
		flag1 = true
	} else {
		recommendation2_2 = append(recommendation2_2, "修改 PASS_MIN_DAYS >= 7")
	}
	num, _ = strconv.Atoi(PASS_MIN_LEN)
	if PASS_WARN_AGE != "/" && num >= 7 {
		flag2 = true
	} else {
		recommendation2_2 = append(recommendation2_2, "修改 PASS_WARN_AGE >= 7")
	}
	num, _ = strconv.Atoi(PASS_MIN_LEN)
	if PASS_MAX_DAYS != "/" && num <= 90 {
		flag3 = true
	} else {
		recommendation2_2 = append(recommendation2_2, "修改 PASS_MAX_DAYS <= 90")
	}
	num, _ = strconv.Atoi(PASS_MIN_LEN)
	if PASS_MIN_LEN != "/" && num >= 8 {
		flag4 = true
	} else {
		recommendation2_2 = append(recommendation2_2, "修改 PASS_MIN_LEN >= 8")
	}
	if len(recommendation2_2) > 0 {
		recommendation2_2 = append([]string{"编辑配置文件\nvim /etc/login.defs\n"}, recommendation2_2...)
	}
	if flag1 && flag2 && flag3 && flag4 {
		result2_2 = "合规"
		*countSuccess++
	} else if !flag1 && !flag2 && !flag3 && !flag4 {
		result2_2 = "不合规"
		*countFail++
	} else {
		result2_2 = "部分合规"
		*countFail++
	}
	info2_2 := "通过限制密码更改的频率，管理员可以防止用户重复更改密码，从而避免密码重用控制。\n提供一个预先警告，密码将会到期给用户时间来考虑一个安全的密码。不知情的用户可能会选择一个简单的密码，或者把它写在可能被发现的地方。\n攻击者利用网络暴力攻击的机会，通过网络暴力攻击的机会窗口，受到密码生存周期的限制。因此，减少密码的生命周期也会减少攻击者的机会窗口。\n增加密码长度可有效增加攻击者爆破难度。"
	standard2_2 := "建议将PASS_MIN_DAYS参数设置为不小于7天。\n建议将PASS_WARN_AGE参数设置为7天。\n建议将PASS_MAX_DAYS参数设置为小于或等于90天。\n建议将PASS_MIN_LEN参数设置为大于或等于8位。"
	data2_2 := []string{
		"2.2", "检查 /etc/login.defs 中的口令策略", "高危", info2_2, "检查 /etc/login.def 中的配置是否符合标准值。",
		standard2_2, "cat /etc/login.defs | grep -v '#' | awk '/PASS_MIN_DAYS/ || /PASS_WARN_AGE/ || /PASS_MAX_DAYS/ || /PASS_MIN_LEN/'",
		strings.Join(recommendation2_2, "\n"), fmt.Sprintf("PASS_MIN_DAYS %s\nPASS_WARN_AGE %s\nPASS_MAX_DAYS %s\nPASS_MIN_LEN %s", PASS_MIN_DAYS, PASS_WARN_AGE, PASS_MAX_DAYS, PASS_MIN_LEN),
		result2_2}
	*xlsxData = append(*xlsxData, data2_2)
	//fmt.Printf("2.2:检查 /etc/login.defs 中的口令策略\t%s\n", result2_2)

	// 2.3:检查是否存在空口令账号
	*countAll++
	var result2_3 string
	var result2_3_data string
	userNoPassword := make([]string, 0)
	shadowContent := StringTextScanner(startCommand(conn, "cat /etc/shadow"))
	for _, line := range strings.Split(shadowContent, "\n") {
		if line == "" {
			break
		}
		fields := strings.Split(line, ":")

		username := fields[0]
		passwordHash := fields[1]

		// 检查密码字段是否为空字符串或为*
		if passwordHash == "/" {
			//fmt.Printf("空口令账户发现: %s\n", username)
			userNoPassword = append(userNoPassword, username)
		}
	}
	if len(userNoPassword) > 0 {
		result2_3_data = "以下账户口令为空：\n" + strings.Join(userNoPassword, "\n")
	} else {
		result2_3_data = "不存在空口令账户"
	}
	if len(userNoPassword) > 0 {
		result2_3 = "不合规"
		*countFail++
	} else {
		result2_3 = "合规"
		*countSuccess++
	}
	data2_3 := []string{
		"2.3", "检查是否存在空口令账户", "高危", "由于空口令会让攻击者不需要口令进入系统，存在较大风险。",
		"查看/etc/passwd，以“:”分隔，第二项若为空，则表示空口令", "不存在空口令账户",
		`"awk -F: \'($2 == '") {print $1}' /etc/shadow"`, "使用passwd命令重设空口令用户密码", result2_3_data, result2_3, "/", "/",
	}
	*xlsxData = append(*xlsxData, data2_3)
	//fmt.Printf("2.3:检查是否存在空口令账号\t%s\t%s\n", result2_3, userNoPassword)

	// 2.4:检查密码重复使用次数限制
	*countAll++
	var result2_4 string
	recommendation2_4 := make([]string, 0)
	result2_4_data := make([]string, 0)
	setPamUnix := false
	setPamPwhistory := false
	var rememberSet int
	passwordComplexityContent := StringTextScanner(startCommand(conn, "cat "+passwordComplexity))
	for _, line := range strings.Split(passwordComplexityContent, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") && strings.Contains(line, "password") && strings.Contains(line, "pam_unix.so") {
			result2_4_data = append(result2_4_data, fmt.Sprintf("pam_unix.so检查记录 [ %s ]", line))
			setPamUnix = true
			for _, item := range strings.Fields(line) {
				if strings.Contains(item, "remember") {
					strLists := strings.Split(item, "=")
					num := strLists[len(strLists)-1]
					rememberSet, _ = strconv.Atoi(num)
				}
			}
		}
		if !strings.HasPrefix(line, "#") && strings.Contains(line, "password") && strings.Contains(line, "pam_pwhistory.so") {
			result2_4_data = append(result2_4_data, fmt.Sprintf("pam_pwhistory.so检查记录 [ %s ]", line))
			setPamPwhistory = true
			for _, item := range strings.Fields(line) {
				if strings.Contains(item, "remember") {
					strLists := strings.Split(item, "=")
					num := strLists[len(strLists)-1]
					rememberSet, _ = strconv.Atoi(num)
				}
			}
		}
	}
	res := rememberSet <= 5
	if res {
		result2_4_data = append(result2_4_data, fmt.Sprintf("口令次数限制为 %d 次 合规", rememberSet))
	} else {
		if setPamUnix {
			recommendation2_4 = append(recommendation2_4, fmt.Sprintf("在 %s中password sufficient pam_unix.so 后添加 remember=5", passwordComplexity))
		} else if setPamPwhistory {
			recommendation2_4 = append(recommendation2_4, fmt.Sprintf("在 %s中password sufficient pam_pwhistory.so 后添加 remember=5", passwordComplexity))
		} else {
			recommendation2_4 = append(recommendation2_4, fmt.Sprintf("在 %s中password sufficient pam_unix.so 后添加 remember=5", passwordComplexity))
		}
		result2_4_data = append(result2_4_data, fmt.Sprintf("未正确设置口令重复使用次数限制，当前设置为 %d", rememberSet))
		recommendation2_4 = append(recommendation2_4, fmt.Sprintf("在 %s中找到类似行password sufficient pam_unix.so，在行末尾增加remember=5，中间以空格隔开。", passwordComplexity))
	}
	existOpasswd := false
	var opasswdStatGood bool
	if StringTextScanner(startCommand(conn, "[[ -e \"/etc/security/opasswd\" ]] && echo \"true\"")) == "true\n" {

		existOpasswd = true

		// 获取文件的实际权限
		rememberSet, _ = strconv.Atoi(getFilePermissions(conn, "/etc/security/opasswd"))

		// 检查权限是否符合安全要求
		if rememberSet == 600 {
			opasswdStatGood = true
		} else {
			opasswdStatGood = false
			result2_4_data = append(result2_4_data, fmt.Sprintf("/etc/security/opasswd 文件权限不合规，当前权限为：%o", rememberSet))
			recommendation2_4 = append(recommendation2_4, "修改 /etc/security/opasswd 文件权限\nchown root:root /etc/security/opasswd\nchmod 600 /etc/security/opasswd")
		}
	} else {
		existOpasswd = false
		result2_4_data = append(result2_4_data, "/etc/security/opasswd 文件不存在")
		recommendation2_4 = append(recommendation2_4, "创建文件/etc/security/opasswd用于存储旧密码，并设置权限。\ntouch /etc/security/opasswd\nchown root:root /etc/security/opasswd\nchmod 600 /etc/security/opasswd")
	}

	recommendation2_4 = append([]string{"配置文件备份\ncp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.bak"}, recommendation2_4...)
	if res && setPamUnix && existOpasswd && opasswdStatGood {
		result2_4 = "合规"
		*countSuccess++
	} else if res || setPamUnix || existOpasswd || opasswdStatGood {
		result2_4 = "部分合规"
		*countFail++
	} else {
		result2_4 = "不合规"
		*countFail++
	}
	data2_4 := []string{
		"2.4", "检查密码重复使用次数限制", "中危",
		"对于采用静态口令认证技术的设备，应配置设备，使用户不能重复使用最近5次（含5次）内已使用的口令。",
		"1、查看文件/etc/pam.d/system-auth，是否有配置口令重复使用次数限制\n2、检查 /etc/security/opasswd 文件权限是否小于等于600",
		"用户不能重复使用最近5次（含5次）内已使用的口令",
		"cat /etc/pam.d/system-auth |sed '/^\\s*#/d'|sed '/^\\s*$/d'|grep -i 'password' | grep pam_unix.so\nstat -c %a /etc/security/opasswd",
		strings.Join(recommendation2_4, "\n"), strings.Join(result2_4_data, "\n"), result2_4, "/", "/"}
	*xlsxData = append(*xlsxData, data2_4)

	//fmt.Printf("2.4: 检查密码重复使用次数限制 %s\n", result2_4)

	// 2.5:检查账户认证失败次数限制
	*countAll++
	result2_5_data := []string{}
	recommendation2_5 := "string"
	//pam_lock := []string{}
	var flag5, flag6 bool

	scanner := bufio.NewScanner(startCommand(conn, "cat "+authSetPath))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") && strings.Contains(line, "auth") && strings.Contains(line, "pam_faillock.so") {
			result2_5_data = append(result2_5_data, line)
			if strings.Contains(line, "preauth") {
				flag1 = true
			}
			if strings.Contains(line, "deny=5") {
				flag2 = true
			}
			if strings.Contains(line, "unlock_time=180") {
				flag3 = true
			}
		}
		if !strings.HasPrefix(line, "#") && strings.Contains(line, "auth") && (strings.Contains(line, "pam_tally2.so") || strings.Contains(line, "pam_tally.so")) {
			result2_5_data = append(result2_5_data, line)
			if strings.Contains(line, "deny=5") {
				flag4 = true
			}
			if strings.Contains(line, "unlock_time=180") {
				flag5 = true
			}
		}
	}
	if flag4 || flag5 {

		scanner = bufio.NewScanner(startCommand(conn, "cat "+accountSetPath))
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			if strings.Contains(line, "account") && strings.Contains(line, "required") && strings.Contains(line, "pam_tally2.so") {
				result2_5_data = append(result2_5_data, line)
				flag6 = true
			}
		}
	}
	result2_5 := "不合规"
	if flag1 && flag2 && flag3 {
		result2_5 = "合规"
		*countSuccess++
	}
	if flag4 && flag5 && flag6 {
		result2_5 = "合规"
		*countSuccess++
	}
	if result2_5 == "不合规" {
		*countFail++
		recommendation2_5 = fmt.Sprintf(`
    查找可用于配置账户认证失败次数限制的动态链接库
	使用包管理器安装mlocate
	updatedb
	locate pam_faillock.so
	locate pam_tally2.so
	locate pam_tally.so
	auth配置文件：%s
	account配置文件：%s
	备份上述配置文件
	cp -p {{配置文件}} {{配置文件}}.bak
	选项1：pam_tally2.so或pam_tally.so
	在相应的文件中编辑或增加如下内容：
	auth required pam_tally2.so deny=5 onerr=fail no_magic_root unlock_time=180
	account required pam_tally2.so
	#(redhat5.1以上版本支持 pam_tally2.so,其他版本使用pam_tally.so)
	选项2：pam_faillock.so
	在相应的文件中编辑或增加如下内容：
	auth required pam_faillock.so preauth silent audit deny=6 unlock_time=180
	auth [success=1 default=ignore] pam_unix.so
	auth required pam_faillock.so authfail audit deny=6 unlock_time=180`, authSetPath, accountSetPath)
	}
	if len(result2_5_data) > 0 {
		result2_5_data = append(result2_5_data, strings.Join(result2_5_data, "\n"))
	} else {
		result2_5_data = append(result2_5_data, "未找到相关配置")
	}
	data2_5 := []string{
		"2.5", "检查账户认证失败次数限制", "中危",
		"对于采用静态口令认证技术的设备，应配置当用户连续认证失败次数超过6次（不含6次），锁定该用户使用的账号。",
		fmt.Sprintf("检查配置文件 %s 是否引用了pam_faillock.so 或 pam_tally.so 或 pam_tally2.so，并配置deny=5、unlock_time=180", authSetPath),
		"用户连续认证失败次数不超过6次，超出后锁定180秒", "cat /etc/pam.d/system-auth | grep -e pam_tally -e pam_faillock.so", recommendation2_5, strings.Join(result2_5_data, "\n"), result2_5, "/", "/",
	}
	*xlsxData = append(*xlsxData, data2_5)
	//fmt.Printf("2.5:检查账户认证失败次数限制\t%s\n", result2_5)

}

// 3
func userAuth(xlsxData *[][]string, countAll *int, countSuccess *int, countFail *int, count_manual *int, conn *ssh.Client, bashrc string) {

	// 3:认证授权
	// 3.1:检查umask设置
	*countAll++
	// 获取 umask
	umask, err := getUmask(conn)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// 将 umask 转换为四位的八进制字符串
	umask1 := fmt.Sprintf("%04o", umask)

	// 正则匹配出数字
	re := regexp.MustCompile(`\d+`)
	match := re.FindString(umask1)
	var result3_1 string
	tmp := []string{"0027", "0077"}
	res := contains(tmp, match)
	if res {
		result3_1 = "合规"
		*countSuccess++
	} else {
		result3_1 = "不合规"
		*countFail++
	}
	data3_1 := []string{
		"3.1", "检查umask命令输出", "中危", "用户umask设置由多个文件控制，请参考子项。",
		"参考子项", "0077或0027", "umask",
		"参考子项", match, result3_1, "/", "/",
	}
	*xlsxData = append(*xlsxData, data3_1)
	//fmt.Printf("3.1:检查umask命令输出\t%s\t%s\n", result3_1, match)

	//isInteger := func(s string) bool {
	//	_, err = strconv.Atoi(s)
	//	return err == nil
	//}
	cmd := "echo $HOME"
	homeDir := StringTextScanner(startCommand(conn, cmd))
	homeDir = strings.Replace(homeDir, "\n", "", -1)
	bashrcPath := homeDir + "/.bashrc"
	login_path := "/etc/login.defs"
	profile_path := "/etc/profile"
	if !res {
		//if !isInteger(match) {
		// 3.1.1:检查~/.bashrc
		*countAll++
		errPrint("获取用户信息错误", err)
		umask_values := []string{}
		var result3_1_1_data string
		var result3_1_1 string
		cmd = "cat " + bashrcPath
		scanner := bufio.NewScanner(startCommand(conn, cmd))
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "#") && strings.Contains(line, "umask") {
				umask_value := strings.TrimSpace(strings.Split(line, " ")[len(strings.Split(line, " "))-1])
				umask_values = append(umask_values, umask_value)
			}
		}
		if len(umask_values) == 0 {
			result3_1_1_data = fmt.Sprintf("%s 中不存在umask", bashrcPath)
			result3_1_1 = "合规"
			*countSuccess++
		} else if len(umask_values) == 1 {
			for _, umask = range umask_values {
				tmpnum := []string{"027", "077"}
				if contains(tmpnum, umask) {
					result3_1_1 = "合规"
					*countSuccess++
					result3_1_1_data = fmt.Sprintf("%s中的umask值：%s", bashrcPath, umask)
				} else {
					result3_1_1 = "不合规"
					result3_1_1_data = fmt.Sprintf("%s中的umask值：%s", bashrcPath, umask)
					*countFail++
				}
			}
		} else {
			result3_1_1 = "人工判断"
			*count_manual++
			result3_1_1_data = fmt.Sprintf("%s中的umask值：\n%s", bashrcPath, strings.Join(umask_values, "\n"))
		}

		data3_1_1 := []string{
			"3.1.1", fmt.Sprintf("检查 %s 中的 umask", bashrcPath), "中危",
			fmt.Sprintf("当用户以交互方式登录时，或者启动新的交互式 Bash shell 时，系统会尝试加载 %s 文件，以读取umask", bashrcPath),
			fmt.Sprintf("检查 %s 中的 umask 是否符合标准值。", bashrcPath), "077或027",
			fmt.Sprintf("cat ~/.bashrc | grep -v '#' | grep umask | /bin/awk  '{print $2}'"),
			fmt.Sprintf("修改 %s 中的 umask 为标准值。", bashrcPath),
			result3_1_1_data, result3_1_1, "/", "/",
		}

		*xlsxData = append(*xlsxData, data3_1_1)
		//fmt.Printf("3.1.1:检查 %s 中的 umask\t%s\t%s\n", bashrcPath, result3_1_1, umask_values)

		// 3.1.2:检查bashrc
		var result3_1_2_data string
		var result3_1_2 string
		*countAll++
		umask_values_bashrc := []string{}
		if StringTextScanner(startCommand(conn, "[[ -e \""+bashrc+"\" ]] && echo \"true\"")) == "true\n" {
			scanner = bufio.NewScanner(startCommand(conn, "cat "+bashrc))
			for scanner.Scan() {
				line := scanner.Text()
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "#") && strings.Contains(line, "umask") {
					umask_value := strings.TrimSpace(strings.Split(line, " ")[len(strings.Split(line, " "))-1])
					umask_values_bashrc = append(umask_values_bashrc, umask_value)
				}
			}
			if len(umask_values_bashrc) == 0 {
				result3_1_2_data = fmt.Sprintf("%s 中不存在umask", bashrc)
				result3_1_2 = "合规"
				*countSuccess++
			} else if len(umask_values_bashrc) == 1 {
				for _, umask = range umask_values_bashrc {
					tmp = []string{"027", "077"}
					if contains(tmp, umask) {
						result3_1_2 = "合规"
						*countSuccess++
						result3_1_2_data = fmt.Sprintf("%s中的umask值：%s", bashrc, umask)
					} else {
						result3_1_2 = "不合规"
						result3_1_2_data = fmt.Sprintf("%s中的umask值：%s", bashrc, umask)
						*countFail++
					}
				}
			} else {
				result3_1_2 = "人工判断"
				*count_manual++
				result3_1_2_data = fmt.Sprintf("%s中的umask值：\n%s", bashrc, strings.Join(umask_values_bashrc, "\n"))
			}
		} else {
			result3_1_2 = "合规"
			*countSuccess++
			result3_1_2_data = fmt.Sprintf("%s 文件不存在", bashrc)
		}

		data3_1_2 := []string{
			"3.1.2", fmt.Sprintf("检查 %s 中的 umask", bashrc), "中危",
			fmt.Sprintf("当用户以交互方式登录时，或者启动新的交互式 Bash shell 时，系统会尝试加载 %s 文件，以读取umask", bashrc),
			fmt.Sprintf("检查 %s 中的 umask 是否符合标准值。", bashrc), "077或027",
			fmt.Sprintf("cat %s | grep -v '#' | grep umask | /bin/awk  '{{print $2}}'", bashrc),
			fmt.Sprintf("修改 %s 中的 umask 为标准值。", bashrc),
			result3_1_2_data, result3_1_2, "/", "/",
		}
		*xlsxData = append(*xlsxData, data3_1_2)
		//fmt.Printf("3.1.2:检查 %s 中的 umask\t%s\t%s\n", bashrc, result3_1_2, umask_values_bashrc)

		// 3.1.3:检查/etc/profile
		*countAll++
		umask_values_profile := []string{}
		var result3_1_3_data string
		var result3_1_3 string

		if StringTextScanner(startCommand(conn, "[[ -e \""+profile_path+"\" ]] && echo \"true\"")) == "true\n" {
			ioRead := startCommand(conn, "cat "+profile_path)
			scanner = bufio.NewScanner(ioRead)
			for scanner.Scan() {
				line := scanner.Text()
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "  ") && strings.Contains(line, "umask") {
					umask_value := strings.TrimSpace(strings.Split(line, " ")[len(strings.Split(line, " "))-1])
					umask_values_profile = append(umask_values_profile, umask_value)
				}
			}
			if len(umask_values_profile) == 0 {
				scanner = bufio.NewScanner(ioRead)
				for scanner.Scan() {
					line := scanner.Text()
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "#") && strings.Contains(line, "umask") {
						umask_value := strings.TrimSpace(strings.Split(line, " ")[len(strings.Split(line, " "))-1])
						umask_values_profile = append(umask_values_profile, umask_value)
					}
				}
			}
			if len(umask_values_profile) == 0 {
				result3_1_3_data = fmt.Sprintf("%s 中不存在umask", profile_path)
				result3_1_3 = "合规"
				*countSuccess++
			} else if len(umask_values_profile) == 1 {
				for _, umask = range umask_values_profile {
					tmp = []string{"027", "077"}
					if contains(tmp, umask) {
						result3_1_3 = "合规"
						*countSuccess++
						result3_1_3_data = fmt.Sprintf("%s中的umask值：%s", profile_path, umask)
					} else {
						result3_1_3 = "不合规"
						*countFail++
						result3_1_3_data = fmt.Sprintf("%s中的umask值：%s", profile_path, umask)
					}
				}
			} else {
				num := 0
				for _, umask = range umask_values_profile {
					tmp = []string{"027", "077"}
					if contains(tmp, umask) {
						num++
					}
				}
				if num == len(umask_values_profile) {
					result3_1_3 = "合规"
					*countSuccess++
					result3_1_3_data = fmt.Sprintf("%s中的umask值：%s", profile_path, umask)
				} else {
					result3_1_3 = "不合规"
					*countFail++
					result3_1_3_data = fmt.Sprintf("%s中的umask值：%s", profile_path, umask)
				}
			}
		} else {
			result3_1_3 = "合规"
			*countSuccess++
			result3_1_3_data = fmt.Sprintf("%s 文件不存在", profile_path)
		}

		data3_1_3 := []string{
			"3.1.3", fmt.Sprintf("检查 %s 中的 umask", profile_path), "中危",
			fmt.Sprintf("当用户登录时，系统会尝试加载 %s 文件，以读取umask", profile_path),
			fmt.Sprintf("检查 %s 中的 umask 是否符合标准值。", profile_path), "077或027",
			"cat /etc/profile | grep -v '#' | grep umask | /bin/awk  '{print $2}'",
			fmt.Sprintf("修改 %s 中的 umask 为标准值。", profile_path), result3_1_3_data, result3_1_3, "/", "/",
		}
		*xlsxData = append(*xlsxData, data3_1_3)
		//fmt.Printf("3.1.3:检查 %s 中的 umask\t%s\t%s\n", profile_path, result3_1_3, umask_values_profile)

		// 3.1.4:检查/etc/login.defs
		*countAll++
		umask_values_login := []string{}
		result3_1_4 := "string"
		result3_1_4_data := "string"

		scanner = bufio.NewScanner(startCommand(conn, "cat "+login_path))
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "#") && strings.Contains(line, "UMASK") {
				umask_value := strings.TrimSpace(strings.Split(line, " ")[len(strings.Split(line, " "))-1])
				re = regexp.MustCompile(`\d+`)
				umask_new_value := re.FindString(umask_value)
				umask_values_login = append(umask_values_login, umask_new_value)
			}
		}
		if len(umask_values_login) == 0 {
			result3_1_4_data = fmt.Sprintf("%s 中不存在umask", login_path)
			result3_1_4 = "合规"
			*countSuccess++
		} else if len(umask_values_login) == 1 {
			for _, umask = range umask_values_login {
				tmp = []string{"027", "077"}
				if contains(tmp, umask) {
					result3_1_4 = "合规"
					*countSuccess++
					result3_1_4_data = fmt.Sprintf("%s中的umask值：%s", login_path, umask)
				} else {
					result3_1_4 = "不合规"
					result3_1_4_data = fmt.Sprintf("%s中的umask值：%s", login_path, umask)
					*countFail++
				}
			}
		} else {
			result3_1_4 = "人工判断"
			*count_manual++
			result3_1_4_data = fmt.Sprintf("%s中的umask值：\n%s", login_path, strings.Join(umask_values_login, "\n"))
		}
		data3_1_4 := []string{
			"3.1.4", fmt.Sprintf("检查 %s 中的 umask", login_path), "中危",
			fmt.Sprintf("当用户登录时，系统会尝试加载 %s 文件，以读取umask", login_path),
			fmt.Sprintf("检查 %s 中的 umask 是否符合标准值。", login_path), "077或027",
			"cat /etc/login.defs | grep -v '#' | grep umask | /bin/awk  '{print $2}'",
			fmt.Sprintf("修改 %s 中的 umask 为标准值。", login_path), result3_1_4_data, result3_1_4, "/", "/",
		}
		*xlsxData = append(*xlsxData, data3_1_4)
		//fmt.Printf("3.1.4:检查 %s 中的 umask\t%s\t%s\n", login_path, result3_1_4, umask_values_login)

	} else {
		*countAll++
		*countSuccess++
		data3_1_1 := []string{
			"3.1.1", fmt.Sprintf("检查 %s 中的 umask", bashrcPath), "中危",
			fmt.Sprintf("当用户以交互方式登录时，或者启动新的交互式 Bash shell 时，系统会尝试加载 %s 文件，以读取umask", bashrcPath),
			fmt.Sprintf("检查 %s 中的 umask 是否符合标准值。", bashrcPath), "077或027",
			fmt.Sprintf("cat ~/.bashrc | grep -v '#' | grep umask | /bin/awk  '{print $2}'"),
			"首项已检",
			"首项已检", "合规", "/", "/",
		}
		*xlsxData = append(*xlsxData, data3_1_1)
		*countAll++
		*countSuccess++
		data3_1_2 := []string{
			"3.1.2", fmt.Sprintf("检查 %s 中的 umask", bashrc), "中危",
			fmt.Sprintf("当用户以交互方式登录时，或者启动新的交互式 Bash shell 时，系统会尝试加载 %s 文件，以读取umask", bashrc),
			fmt.Sprintf("检查 %s 中的 umask 是否符合标准值。", bashrc), "077或027",
			fmt.Sprintf("cat %s | grep -v '#' | grep umask | /bin/awk  '{{print $2}}'", bashrc),
			"首项已检",
			"首项已检", "合规", "/", "/",
		}
		*xlsxData = append(*xlsxData, data3_1_2)
		*countAll++
		*countSuccess++
		data3_1_3 := []string{
			"3.1.3", fmt.Sprintf("检查 %s 中的 umask", profile_path), "中危",
			fmt.Sprintf("当用户登录时，系统会尝试加载 %s 文件，以读取umask", profile_path),
			fmt.Sprintf("检查 %s 中的 umask 是否符合标准值。", profile_path), "077或027",
			"cat /etc/profile | grep -v '#' | grep umask | /bin/awk  '{print $2}'",
			"首项已检",
			"首项已检", "合规", "/", "/",
		}
		*xlsxData = append(*xlsxData, data3_1_3)
		*countAll++
		*countSuccess++
		data3_1_4 := []string{
			"3.1.4", fmt.Sprintf("检查 %s 中的 umask", login_path), "中危",
			fmt.Sprintf("当用户登录时，系统会尝试加载 %s 文件，以读取umask", login_path),
			fmt.Sprintf("检查 %s 中的 umask 是否符合标准值。", login_path), "077或027",
			"cat /etc/login.defs | grep -v '#' | grep umask | /bin/awk  '{print $2}'",
			"首项已检",
			"首项已检", "合规", "/", "/",
		}
		*xlsxData = append(*xlsxData, data3_1_4)
	}

	// 3.2:检查是否设置SSH登录前警告Banner
	*countAll++
	bannerPath := "/"
	result3_2Data := "未设置 Banner"
	result3_2 := "string"
	scanner := bufio.NewScanner(startCommand(conn, "cat /etc/ssh/sshd_config"))
	var output strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		output.WriteString(line + "\n")
	}
	for _, line := range strings.Split(output.String(), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") && strings.Contains(line, "Banner") {
			parts := strings.Split(line, " ")
			if len(parts) == 2 {
				bannerPath = parts[1]
			} else {
				result3_2 = "不合规"
				*countFail++
				result3_2Data = fmt.Sprintf("Banner 设置异常\n %s", line)
			}
		}
	}
	if bannerPath != "/" {
		scanner = bufio.NewScanner(startCommand(conn, "cat "+bannerPath))
		var output1 strings.Builder
		for scanner.Scan() {
			line := scanner.Text()
			output1.WriteString(line + "\n")
		}
		if len(output.String()) > 0 {
			result3_2 = "合规"
			*countSuccess++
			result3_2Data = strings.TrimSpace(output.String())
		} else {
			result3_2 = "不合规"
			*countFail++
			result3_2Data = fmt.Sprintf("Banner指向的文件 %s 为空", bannerPath)
		}
	} else {
		result3_2 = "不合规"
		*countFail++
		result3_2Data = "未设置 Banner"
	}
	recommendation3_2 := `
	1、编辑文件/etc/ssh/sshd_config文件，修改Banner参数的值如下(如不存在则新增)：
	Banner /etc/ssh_banner
	2、执行如下命令创建SSH banner警示信息文件：
	touch /etc/ssh_banner
	chmod 644 /etc/ssh_banner
	echo "Authorized only. All activity will be monitored and reported" > /etc/ssh_banner
	可根据实际需要修改该文件的内容。
	3、重启sshd服务:
	/etc/init.d/sshd restart`
	data3_2 := []string{
		"3.2", "检查是否设置SSH登录前警告Banner", "中危", "ssh登陆前的警告Banner信息用于警示登陆系统的人员",
		"检查SSH配置文件: /etc/ssh/sshd_config 是否启用banner并合理设置banner的内容", "启用banner并合理设置banner的内容",
		"cat /etc/ssh/sshd_config | grep -v '#' | grep Banner\ncat {Banner设置指向的文件}", recommendation3_2,
		result3_2Data, result3_2, "/", "/",
	}
	*xlsxData = append(*xlsxData, data3_2)
	//fmt.Printf("3.2:检查是否设置SSH登录前警告Banner\t%s\t%s\n", result3_2, result3_2Data)

}

// 4
func SshLog(xlsxData *[][]string, countAll *int, countSuccess *int, countFail *int, conn *ssh.Client) {

	// 4:日志审计
	// 4.1:检查安全事件日志配置
	*countAll++
	syslogConf := map[string][]string{
		"/var/log/messages": {"*.info", "mail.none", "authpriv.none", "cron.none"},
		"/var/log/secure":   {"authpriv.*"},
		"/var/log/cron":     {"cron.*"},
	}
	logsNoSet := make(map[string][]string)
	standardList := make([]string, 0)
	var result4_1_data []string
	for path, logs := range syslogConf {
		logNoSet := make([]string, 0)
		standardList = append(standardList, strings.Join(logs, ";")+"    "+path)
		for _, log1 := range logs {
			isSetLog := false
			session, _ := conn.NewSession()
			stdout, err := session.StdoutPipe()
			if err = session.Run("cat /etc/rsyslog.conf"); err != nil {
				stdout, err = session.StdoutPipe()
				if err = session.Run("cat /etc/systemd/journald.conf"); err != nil {
					result4_1_data = append(result4_1_data, "/etc/systemd/journald.conf以及/etc/rsyslog.conf打开失败")
					break
				}
			}
			scanner := bufio.NewScanner(stdout)
			var output strings.Builder

			for scanner.Scan() {
				line := scanner.Text()
				output.WriteString(line + "\n")
			}
			for _, line := range strings.Split(output.String(), "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "#") && strings.Contains(line, log1) && strings.Contains(line, path) {
					isSetLog = true
					result4_1_data = append(result4_1_data, line)
				}
			}
			if !isSetLog {
				logNoSet = append(logNoSet, log1)
			}
		}
		if len(logNoSet) > 0 {
			logsNoSet[path] = logNoSet
		}
	}
	standard := strings.Join(standardList, "\n")
	result4_1_data_str := strings.Join(result4_1_data, "\n")
	recommendation4_1 := "string"
	result4_1 := "string"

	if len(logsNoSet) > 0 {
		result4_1 = "不合规"
		*countFail++
		recommendation4_1 = "在 /etc/rsyslog.conf 中写入: \n"
		if _, ok := logsNoSet["0"]; ok {
			result4_1_data_str = result4_1_data_str + "\t" + "未安装rsyslog日志记录服务"
		} else {
			for path, logs := range logsNoSet {
				log1 := strings.Join(logs, ";")
				result4_1_data_str = result4_1_data_str + fmt.Sprintf("未将 %s 指向 %s", log1, path)
				recommendation4_1 += fmt.Sprintf("%s {{多个制表符}} %s\n", log1, path)
			}
			result4_1_data_str = strings.TrimSpace(result4_1_data_str)
			recommendation4_1 = strings.TrimSpace(recommendation4_1)
		}

	} else {
		result4_1 = "合规"
		*countSuccess++
		recommendation4_1 = "/"
	}
	data4_1 := []string{
		"4.1", "检查安全事件日志配置", "高危", "应对安全事件日志文件进行配置",
		"检查 /etc/rsyslog.conf 中是否按标准值配置了日志保存路径", standard, "cat /etc/rsyslog.conf | grep -v '#' | grep -v '^$'", recommendation4_1,
		result4_1_data_str, result4_1, "/", "/",
	}
	*xlsxData = append(*xlsxData, data4_1)
	//fmt.Printf("4.1:检查安全事件日志配置\t%s\n", result4_1)

	// 4.2:检查日志文件权限设置
	*countAll++
	permissionDict := map[string]int{
		"/var/log/messages": 600,
		//"/var/log/secure":   600,
		"/var/log/auth.log": 600,
		//"/var/log/maillog":  600,
		"/var/log/mail.log": 600,
		//"/var/log/cron":     600,
		"/var/log/syslog": 600,
		"/var/log/dmesg":  644,
		"/var/log/wtmp":   644,
	}

	permissionRecommendation := make([]string, 0)
	result4_2Data := make([]string, 0)
	recommendation4_2 := make([]string, 0)
	flag4_2 := true
	result := "string"
	var recommendation4_2_str string

	for file, permissionSet := range permissionDict {
		permissionRecommendation = append(permissionRecommendation, fmt.Sprintf("%s\t%d", file, permissionSet))
		if StringTextScanner(startCommand(conn, "[[ -e \""+file+"\" ]] && echo \"true\"")) == "true\n" {

			strFileStat := getFilePermissions(conn, file)
			intFileStat, _ := strconv.Atoi(strFileStat)
			if intFileStat <= permissionSet {
				result = "合规"
			} else {
				result = "不合规"
				flag4_2 = false
				recommendation := fmt.Sprintf("修改%s文件权限\nchmod %d %s", file, permissionSet, file)
				recommendation4_2 = append(recommendation4_2, recommendation)
			}
			result4_2Data = append(result4_2Data, fmt.Sprintf("%s 权限\t%d\t%s", file, intFileStat, result))
		} else {
			flag4_2 = false
			result4_2Data = append(result4_2Data, fmt.Sprintf("%s 文件不存在\t", file))
			//result4_2Data = append(result4_2Data, fmt.Sprintf("%s 文件不存在\t不合规", file))
			recommendation := fmt.Sprintf("创建%s,并设置权限\ntouch %s\nchmod %d %s", file, file, permissionSet, file)
			recommendation4_2 = append(recommendation4_2, recommendation)
		}
	}

	if len(recommendation4_2) > 0 {
		recommendation4_2 = append(recommendation4_2, "重启syslog服务\n/etc/init.d/rsyslog restart")
		recommendation4_2_str = strings.Join(recommendation4_2, "\n")
	}

	var result4_2 string
	var result4_2Data_str string
	var permissionRecommendation_str string
	result4_2Data_str = strings.Join(result4_2Data, "\n")
	permissionRecommendation_str = strings.Join(permissionRecommendation, "\n")

	if flag4_2 {
		result4_2 = "合规"
		*countSuccess++
		//fmt.Printf("4.2:检查日志文件权限设置\t%s\n", result4_2)
	} else {
		result4_2 = "不合规"
		*countFail++
		//fmt.Printf("4.2:检查日志文件权限设置\t%s\n", result4_2)
	}

	data4_2 := []string{
		"4.2", "检查日志文件权限设置", "中危",
		"设备应配置权限，控制对日志文件读取、修改和删除等操作\n/var/log/messages\t系统日志\n/var/log/maillog\t邮件系统日志\n/var/log/secure\t安全信息，系统登录与网络连接的信息\n/var/log/dmesg\t核心启动日志\n/var/log/wtmp\t登录记录\n/var/log/cron\tcron(定制任务日志)日志",
		"检查日志文件权限是否小于等于标准值", permissionRecommendation_str, "ls -l {目标文件} 或 stat -c %a {目标文件}",
		recommendation4_2_str, result4_2Data_str, result4_2, "/", "/",
	}
	*xlsxData = append(*xlsxData, data4_2)

	// 4.3:检查是否配置远程日志功能
	*countAll++
	outputString := StringTextScanner(startCommand(conn, "service rsyslog status"))

	var result4_3 string
	result4_3Data := make([]string, 0)
	recommendation4_3 := make([]string, 0)
	//recommendation4_3Command := make([]string, 0)
	var flag4_3_1, flag4_3_2, flag4_3_3 bool
	if strings.Contains(outputString, "Active") {
		if strings.Contains(outputString, "Active: active (running)") {
			result4_3Data = append(result4_3Data, "rsyslog 服务正在运行")
			flag4_3_1 = true
		} else {
			result4_3Data = append(result4_3Data, "rsyslog 服务未运行")
			flag4_3_1 = false
			recommendation4_3 = append(recommendation4_3, "运行 rsyslog 服务")
			//recommendation4_3Command = append(recommendation4_3Command, "service rsyslog start")
		}
		for _, line := range strings.Split(outputString, "\n") {
			if strings.HasPrefix(line, "Loaded") {
				if !strings.Contains(line, "disabled;") {
					result4_3Data = append(result4_3Data, "rsyslog 服务已启用")
					flag4_3_2 = true
				} else {
					result4_3Data = append(result4_3Data, "rsyslog 服务未启用")
					recommendation4_3 = append(recommendation4_3, "启用 rsyslog 服务")
					//recommendation4_3Command = append(recommendation4_3Command, "systemctl enable rsyslog")
					flag4_3_2 = false
				}
			}
		}
	} else if strings.Contains(outputString, "is running...") || strings.Contains(outputString, "is stopped") {
		if strings.Contains(outputString, "is running...") {
			result4_3Data = append(result4_3Data, "rsyslog 服务正在运行")
			flag4_3_1 = true
		} else {
			result4_3Data = append(result4_3Data, "rsyslog 服务未运行")
			flag4_3_1 = false
			recommendation4_3 = append(recommendation4_3, "运行 rsyslog 服务")
			//recommendation4_3Command = append(recommendation4_3Command, "service rsyslog start")
		}
		chkconfigOutput := StringTextScanner(startCommand(conn, "chkconfig --list | grep rsyslog"))

		if strings.Contains(chkconfigOutput, "on") {
			result4_3Data = append(result4_3Data, "rsyslog 服务已启用")
			flag4_3_2 = true
		} else {
			result4_3Data = append(result4_3Data, "rsyslog 服务未启用")
			recommendation4_3 = append(recommendation4_3, "启用 rsyslog 服务")
			//recommendation4_3Command = append(recommendation4_3Command, "systemctl enable rsyslog")
			flag4_3_2 = false
		}
	}
	if StringTextScanner(startCommand(conn, "[[ -e \"/etc/rsyslog.conf\" ]] && echo \"true\"")) == "true\n" {
		mark := "/"
		rsyslog := StringTextScanner(startCommand(conn, "cat /etc/rsyslog.conf"))
		for _, line := range strings.Split(rsyslog, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "#") && strings.Contains(line, "@") {
				mark = line
				result4_3Data = append(result4_3Data, line)
				flag4_3_3 = true
			}
		}
		if mark == "/" {
			recommendation4_3 = append(recommendation4_3, fmt.Sprintf("根据需求在 /etc/rsyslog.conf 中添加或修改，{日志类型}.{日志级别}{制表符}@{日志服务器IP}:{端口}，详情参考 /etc/rsyslog.conf 中的注释\n重启 syslog 服务\n service rsyslog restart"))
			//recommendation4_3Command = append(recommendation4_3Command, "请根据需求修改 /etc/rsyslog.conf")
			result4_3Data = append(result4_3Data, "rsyslog.conf 未正确配置")
		}
	} else {
		result4_3Data = append(result4_3Data, "/etc/rsyslog.conf 文件不存在")
	}
	if (flag4_3_1 || flag4_3_2) && flag4_3_3 {
		result4_3 = "合规"
		*countSuccess++
	} else if flag4_3_1 || flag4_3_2 || flag4_3_3 {
		if !flag4_3_3 {
			recommendation4_3 = append(recommendation4_3, fmt.Sprintf("根据需求在 /etc/rsyslog.conf 中添加或修改，{日志类型}.{日志级别}{制表符}@{日志服务器IP}:{端口}，详情参考 /etc/rsyslog.conf 中的注释\n重启 syslog 服务\n service rsyslog restart"))
		}
		result4_3 = "部分合规"
		*countFail++
	} else {
		result4_3 = "不合规"
		*countFail++
	}
	recommendation4_3Message := strings.Join(recommendation4_3, "\n")
	//recommendation4_3CommandMessage := strings.Join(recommendation4_3Command, "\n")
	result4_3DataMessage := strings.Join(result4_3Data, "\n")
	data4_3 := []string{
		"4.3", "检查是否配置远程日志功能", "中危", "日志应统一管理",
		"检查 rsyslog 服务启动并启用，检查 /etc/rsyslog.conf 是否正确配置日志转发。", "按需将日志转发至远程服务器",
		"service rsyslog status\n cat /etc/rsyslog.conf | grep -v '#' | grep '@'", recommendation4_3Message,
		result4_3DataMessage, result4_3, "/", "/",
	}
	*xlsxData = append(*xlsxData, data4_3)

	//fmt.Printf("4.3:检查是否配置远程日志功能\t%s\n", result4_3)

	// 4.4:检查是否启用审计服务
	*countAll++
	var result4_4Data string
	var result4_4 string
	auditOutput := StringTextScanner(startCommand(conn, "ps -ef | grep auditd | grep -v grep | grep -v kauditd"))
	recommendation4_4 := `使用包管理器安装auditd,启用并启动auditd 服务`
	if len(auditOutput) == 0 {
		result4_4Data = "auditd 未启动"
		*countFail++
		result4_4 = "不合规"
		//fmt.Println("4.4:检查是否启用审计服务\t不合规")
	} else {
		result4_4Data = "auditd 已启动"
		*countSuccess++
		result4_4 = "合规"
		//fmt.Println("4.4:检查是否启用审计服务\t合规")
		recommendation4_4 = "/"
	}
	data4_4 := []string{
		"4.4", "检查是否启用审计服务", "中危",
		"应启用auditd，auditd 是 Linux 操作系统上用于审计的守护进程。它是 Linux 内核审计框架的用户空间组件，负责收集、处理和记录与系统安全相关的事件。审计日志记录的信息包括用户登录、文件访问、进程创建和终止、系统调用等。",
		"auditd 已启动", "/", "ps -ef | grep auditd | grep -v grep | grep -v kauditd", recommendation4_4, result4_4Data,
		result4_4, "/", "/",
	}
	*xlsxData = append(*xlsxData, data4_4)
}

// 5
func Ftp_Telnet_Snmp(xlsxData *[][]string, countAll *int, countSuccess *int, countFail *int, conn *ssh.Client) {
	*countAll++
	flag5_1 := true
	var result string
	var result5_1 string
	result5_1Data := []string{}
	permissionRecommendation := []string{}
	recommendation5_1 := []string{}
	permissionDict := map[string]string{
		"/etc/shadow":   "400",
		"/etc/passwd":   "644",
		"/etc/group":    "644",
		"/etc":          "755",
		"/etc/security": "755",
		"/etc/services": "644",
		//"/etc/grub.conf":      600,
		"/etc/grub/grub.conf": "600",
		"/boot/grub/grub.cfg": "600",
		"/etc/default/grub":   "600",
		//"/etc/lilo.conf":      600,
		"/etc/systemd/system": "600",
		"/tmp":                "750",
		//"/etc/rc.d/init.d":    755,
		"/lib/systemd/system/": "755",
		"/etc/xinetd.conf":     "600",
		"/etc/inetd.conf":      "600",
	}
	permissionCheckFalse := []string{}
	for path, permissionSet := range permissionDict {
		permissionRecommendation = append(permissionRecommendation, fmt.Sprintf("%s\t%s", path, permissionSet))
		if StringTextScanner(startCommand(conn, "[[ -e \""+path+"\" ]] && echo \"true\"")) == "true\n" {

			strFileStat := getFilePermissions(conn, path)
			intpermissionSet, _ := strconv.Atoi(permissionSet)
			intFileStat, _ := strconv.Atoi(strFileStat)
			if intFileStat <= intpermissionSet {
				result = "合规"
			} else {
				result = "不合规"
				flag5_1 = false
				recommendation := fmt.Sprintf("# 修改%s文件权限\nchmod %s %s", path, permissionSet, path)
				recommendation5_1 = append(recommendation5_1, recommendation)
				permissionCheckFalse = append(permissionCheckFalse, path)
			}
			result5_1Data = append(result5_1Data, fmt.Sprintf("%s 权限\t%d\t%s", path, intFileStat, result))
		} else {
			result5_1Data = append(result5_1Data, fmt.Sprintf("%s 文件不存在\t合规", path))
		}
	}
	if flag5_1 {
		result5_1 = "合规"
		*countSuccess++
		//fmt.Printf("5.1:检查重要目录或文件权限设置\t%s\n", result5_1)
	} else {
		result5_1 = "不合规"
		*countFail++
		//fmt.Printf("5.1:检查重要目录或文件权限设置\t%s\n", result5_1)
		recommendation5_1 = append(recommendation5_1, fmt.Sprintf("# 重新检查权限\nstat -c '%%a' %s", permissionCheckFalse))
	}
	newPermissionRecommendation := strings.Join(permissionRecommendation, "\n")
	newRecommendation5_1 := strings.Join(recommendation5_1, "\n")
	newResult5_1Data := strings.Join(result5_1Data, "\n")
	data5_1 := []string{
		"5.1", "检查重要目录或文件权限设置", "中危", "在设备权限配置能力内，根据用户的业务需要，配置其所需的最小权限。",
		"检查目标权限是否小于等于标准值", newPermissionRecommendation, "ls -l {目标} 或 stat -c '%a' {目标}", newRecommendation5_1,
		newResult5_1Data, result5_1, "/", "/",
	}
	*xlsxData = append(*xlsxData, data5_1)

	var result5_2 string

	*countAll++
	result5_2Data := []string{}
	recommendation5_2 := []string{}

	// Check FTP process
	cmd := "sh -c ps -ef | grep ftpd | grep -v grep | wc -l"
	ftpOutput := StringTextScanner(startCommand(conn, cmd))
	ftpStat := strings.TrimSpace(ftpOutput)

	if ftpStat == "0" || ftpStat == "" {
		result5_2Data = append(result5_2Data, "FTP进程不存在")
		result5_2 = "合规"
		*countSuccess++
		//fmt.Println("5.2:检查FTP用户上传的文件所具有的权限\t合规")
		result5_2DataStr := strings.Join(result5_2Data, "\n")
		data5_2 := []string{
			"5.2", "检查FTP用户上传的文件所具有的权限", "中危", "设置FTP用户登录后对文件目录的存取权限。",
			"检查FTP进程，若不存在，则合规；否则检查 /etc/vsftpd/vsftpd.conf 中 local_umask、anon_umask 配置是否符合标准",
			"FTP进程不存在或local_umask、anon_umask=022",
			"ps -ef|grep ftpd|grep -v grep\ncat /etc/vsftpd/vsftpd.conf|grep -v \"^[[:space:]]*#\"|grep \"local_umask\"\ncat /etc/vsftpd/vsftpd.conf|grep -v \"^[[:space:]]*#\"|grep \"anon_umask\"/",
			"/", result5_2DataStr, result5_2, "/", "/",
		}
		*xlsxData = append(*xlsxData, data5_2)
		return
	}

	// 检查 local_umask
	vsftpdpath := "/etc/vsftpd/vsftpd.conf"
	resoult := true
	if StringTextScanner(startCommand(conn, "[[ -e "+vsftpdpath+" ]] && echo \"true\"")) != "true\n" {
		if StringTextScanner(startCommand(conn, "[[ -e \"/etc/vsftpd.conf\" ]] && echo \"true\"")) == "true\n" {
			vsftpdpath = "/etc/vsftpd.conf"
		} else {
			resoult = false
		}
	}
	if resoult == false {
		return
	}
	cmd = "sh -c cat " + vsftpdpath + " | grep -v '^[[:space:]]*#' | grep local_umask"
	localUmaskOutput := StringTextScanner(startCommand(conn, cmd))

	localUmask := strings.TrimSpace(localUmaskOutput)
	localUmaskFlag := false
	if localUmask != "/" {
		//localUmaskNum, err := strconv.Atoi(strings.Split(localUmask, "=")[1])
		//if err != nil {
		//	fmt.Printf("Error converting umask to integer: %v\n", err)
		//	return
		//}
		parts := strings.Split(localUmask, "=")
		if len(parts) < 2 {
			fmt.Println("Error: Invalid format for localUmask")
			return
		}
		// 获取 umask 值
		umaskStr := parts[1]
		// 将字符串转换为整数
		localUmaskNum, err := strconv.Atoi(umaskStr)
		if err != nil {
			fmt.Printf("Error converting umask to integer: %v\n", err)
			return
		}
		if localUmaskNum == 22 {
			localUmaskFlag = true
			result5_2Data = append(result5_2Data, fmt.Sprintf("%s\t合规", localUmask))
		} else {
			result5_2Data = append(result5_2Data, fmt.Sprintf("%s\t不合规", localUmask))
			recommendation5_2 = append(recommendation5_2, "在 /etc/vsftpd/vsftpd.conf 中修改 local_umask=022")
		}
	} else {
		result5_2Data = append(result5_2Data, "local_umask 未设置")
		recommendation5_2 = append(recommendation5_2, "在 /etc/vsftpd/vsftpd.conf 中添加 local_umask=022")
	}

	// 检查 anon_umask
	cmd = "sh -c cat " + vsftpdpath + " | grep -v '^[[:space:]]*#' | grep anon_umask"
	anonUmaskOutput := StringTextScanner(startCommand(conn, cmd))
	anonUmaskFlag := false
	anonUmask := strings.TrimSpace(anonUmaskOutput)
	if anonUmask != "/" {
		anonUmaskNum, err := strconv.Atoi(strings.Split(anonUmask, "=")[1])
		if err != nil {
			fmt.Println("Error converting anon umask:", err)
			return
		}
		if anonUmaskNum == 22 {
			anonUmaskFlag = true
			result5_2Data = append(result5_2Data, fmt.Sprintf("%s\t合规", anonUmask))
		} else {
			result5_2Data = append(result5_2Data, fmt.Sprintf("%s\t不合规", anonUmask))
			recommendation5_2 = append(recommendation5_2, "在 /etc/vsftpd/vsftpd.conf 中修改 anon_umask=022")
		}
	} else {
		result5_2Data = append(result5_2Data, "anon_umask 未设置")
		recommendation5_2 = append(recommendation5_2, "在 /etc/vsftpd/vsftpd.conf 中添加 anon_umask=022")
	}

	// Final result
	if localUmaskFlag && anonUmaskFlag {
		result5_2 = "合规"
		*countSuccess++
		//fmt.Println("5.2:检查FTP用户上传的文件所具有的权限\t合规")
	} else {
		result5_2 = "不合规"
		*countFail++
		//fmt.Println("5.2:检查FTP用户上传的文件所具有的权限\t不合规")
	}

	result5_2DataStr := strings.Join(result5_2Data, "\n")
	recommendation5_2Str := strings.Join(recommendation5_2, "\n")
	data5_2 := []string{
		"5.2", "检查FTP用户上传的文件所具有的权限", "中危", "设置FTP用户登录后对文件目录的存取权限。",
		"检查FTP进程，若不存在，则合规；否则检查 /etc/vsftpd/vsftpd.conf 中 local_umask、anon_umask 配置是否符合标准",
		"FTP进程不存在或local_umask、anon_umask=022",
		"ps -ef|grep ftpd|grep -v grep\ncat /etc/vsftpd/vsftpd.conf|grep -v \"^[[:space:]]*#\"|grep \"local_umask\"\ncat /etc/vsftpd/vsftpd.conf|grep -v \"^[[:space:]]*#\"|grep \"anon_umask\"/",
		recommendation5_2Str, result5_2DataStr, result5_2, "/", "/",
	}
	*xlsxData = append(*xlsxData, data5_2)
}

// 6
func Openssh_Root(xlsxData *[][]string, countAll *int, countSuccess *int, countFail *int, count_manual *int, conn *ssh.Client) {

	// 6:网络通信
	// 6.1:检查是否禁用Telnet协议
	*countAll++
	cmd := "ps -ef | grep inetd | grep -v grep"
	telnetOutput := StringTextScanner(startCommand(conn, cmd))
	if telnetOutput == "exit status 1" {
		recommendation6_1 := "/"
		result6_1Data := "/"
		result6_1 := "执行失败"
		data6_1 := []string{
			"6.1", "检查是否禁用Telnet协议", "高危", "不应使用不安全的Telnet进行远程管理。",
			"检查Telnet服务是否启动", "Telnet 已禁用", "ps -ef | grep inetd | grep -v grep\nps -ef | grep xinetd | grep -v grep", recommendation6_1, result6_1Data, result6_1, "/", "/",
		}
		*xlsxData = append(*xlsxData, data6_1)
	} else {
		//fmt.Println("6.1:检查是否禁用Telnet协议命令输出：|", reflect.TypeOf(telnetOutput), "|", telnetOutput, "|")
		var telnetOutput1 string
		if telnetOutput == "" {
			cmd = "ps -ef | grep xinetd | grep -v grep"
			telnetOutput1 = StringTextScanner(startCommand(conn, cmd))
		}
		var recommendation6_1 string
		var result6_1 string
		var result6_1Data string
		//res := make([]uint8, 1)
		if len(telnetOutput1) > 0 {
			result6_1 = "不合规"
			*countFail++
			//fmt.Println("6.1:检查是否禁用Telnet协议\t不合规")
			result6_1Data = strings.TrimSpace(telnetOutput)
			recommendation6_1 = `
关闭Telnet服务xinetd或inetd：
以下以xinetd为例
备份
cp -p /etc/xinetd.d/telnet /etc/xinetd.d/telnet_bak
编辑文件/etc/xinetd.d/telnet，把disable项改为yes.
执行以下命令重启xinetd服务。
service xinetd restart`
		} else {
			result6_1 = "合规"
			//fmt.Println("6.1:检查是否禁用Telnet协议\t合规")
			*countSuccess++
			result6_1Data = "Telnet 已禁用"
			data6_1 := []string{
				"6.1", "检查是否禁用Telnet协议", "高危", "不应使用不安全的Telnet进行远程管理。",
				"检查Telnet服务是否启动", "Telnet 已禁用", "ps -ef | grep inetd | grep -v grep\nps -ef | grep xinetd | grep -v grep", recommendation6_1, result6_1Data, result6_1, "/", "/",
			}
			*xlsxData = append(*xlsxData, data6_1)
		}
		//}
		// 6.2:检查是否使用PAM认证模块禁止wheel组之外的用户su为root
		*countAll++
		suFilePath := "/etc/pam.d/su"
		result6_2Data := "未使用PAM认证模块禁止wheel组之外的用户su为root"
		result6_2 := "不合规"
		recommendation6_2 := `
编辑文件/etc/pam.d/su
在文件开头加入如下两行(有则修改,没有则添加):
auth sufficient pam_rootok.so
auth required pam_wheel.so use_uid
#注意auth与sufficient之间由两个tab建隔开，sufficient与动态库路径之间使用一个tab建隔开
说明：(这表明只有wheel组中的用户可以使用su命令成为root用户。你可以把用户添加到wheel组，以使它可以使用su命令成为root用户。)
添加方法:
#usermod -G wheel username #username为需要添加至wheel组的账户名称。`
		if StringTextScanner(startCommand(conn, "[[ -e \""+suFilePath+"\" ]] && echo \"true\"")) == "true\n" {
			file := startCommand(conn, "cat "+suFilePath)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if !strings.HasPrefix(line, "#") && strings.Contains(line, "pam_wheel.so") {
					result6_2Data = line
					result6_2 = "合规"
					break
				}
			}
		} else if StringTextScanner(startCommand(conn, "[[ -e \""+suFilePath+"\" ]] && echo \"true\"")) != "true" {
			result6_2Data = fmt.Sprintf("%s 不存在", suFilePath)
		}
		//fmt.Println("6.2:检查是否使用PAM认证模块禁止wheel组之外的用户su为root\t 不合规")
		data6_2 := []string{
			"6.2", "检查是否使用PAM认证模块禁止wheel组之外的用户su为root", "高危",
			"应使用PAM认证模块禁止wheel组之外的用户su为root",
			fmt.Sprintf("检查%s 是否使用PAM认证模块禁止wheel组之外的用户su为root", suFilePath), "使用PAM认证模块禁止wheel组之外的用户su为root", "cat /etc/pam.d/su | grep -v '#' | grep auth | grep pam_wheel.so", recommendation6_2, result6_2Data,
			result6_2, "/", "/",
		}
		*xlsxData = append(*xlsxData, data6_2)
	}

	// 6.3:是否修改SNMP默认团体字
	*countAll++
	result6_3Data := []string{}
	recommendation6_3 := []string{}
	result6_3 := "不合规"
	snmpdConf := "/etc/snmp/snmpd.conf"
	cmd = "ps -ef | grep snmpd | egrep -v grep | wc -l"
	snmpOutput := StringTextScanner(startCommand(conn, cmd))
	if snmpOutput == "exit status 1" {
		recommendation6_3Str := "/"
		result6_3DataStr := "/"
		result6_3 = "执行失败"
		data6_3 := []string{
			"6.3", "检查是否修改SNMP默认团体字", "中危",
			"如果没有必要，需要停止SNMP服务，如果确实需要使用SNMP服务，需要修改SNMP Community。",
			"检查snmpd服务是否已启动，若已启动，则检查是否修改团体名，否则合规。", "未启动snmp服务，或已修改团体名",
			"ps -ef|grep snmpd|egrep -v \"grep\"|wc -l\nvim /etc/snmp/snmpd.conf", recommendation6_3Str, result6_3DataStr, result6_3, "/", "/",
		}
		*count_manual++
		*xlsxData = append(*xlsxData, data6_3)
	} else {
		snmpOutputStr := strings.TrimSpace(snmpOutput)
		snmpPubilc := false
		if snmpOutputStr == "0" || snmpOutputStr == "" || reflect.TypeOf(snmpOutputStr) == reflect.TypeOf(int(0)) {
			result6_3 = "合规"
			result6_3Data = append(result6_3Data, "snmp服务未启动")
		} else {
			result6_3Data = append(result6_3Data, "snmp服务已启动")
			if StringTextScanner(startCommand(conn, "[[ -e \""+snmpdConf+"\" ]] && echo \"true\"")) == "true\n" {
				file := startCommand(conn, "cat "+snmpdConf)
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := scanner.Text()
					if strings.HasPrefix(line, "rocommunity") {
						if strings.Contains(line, "public") {
							result6_3Data = append(result6_3Data, fmt.Sprintf("%s\t不合规", line))
							snmpPubilc = true
						} else {
							result6_3Data = append(result6_3Data, fmt.Sprintf("%s\t合规", line))
						}
					}
				}
				if err := scanner.Err(); err != nil {
					fmt.Println("6.3 Error reading snmpd.conf file:", err)
					return
				}
				if snmpPubilc {
					result6_3 = "不合规"
					recommendation6_3 = append(recommendation6_3, fmt.Sprintf("修改snmp配置文件/etc/snmp/snmpd.conf找到类似如下配置,修改默认团体名public为其他用户自己可识别的字符串\nrocommunity  public default -V systemonly\n重启snmp服务\nservice snmpd restart"))
				} else {
					result6_3 = "合规"
				}
			} else {
				result6_3Data = append(result6_3Data, fmt.Sprintf("%s 不存在", snmpdConf))
			}
		}
		recommendation6_3Str := strings.Join(recommendation6_3, "\n")
		result6_3DataStr := strings.Join(result6_3Data, "\n")
		if result6_3 == "合规" {
			*countSuccess++
			//fmt.Println("6.3:检查是否修改SNMP默认团体字\t 合规")
		} else {
			*countFail++
			//fmt.Println("6.3:检查是否修改SNMP默认团体字\t 不合规")
		}
		data6_3 := []string{
			"6.3", "检查是否修改SNMP默认团体字", "中危",
			"如果没有必要，需要停止SNMP服务，如果确实需要使用SNMP服务，需要修改SNMP Community。",
			"检查snmpd服务是否已启动，若已启动，则检查是否修改团体名，否则合规。", "未启动snmp服务，或已修改团体名",
			"ps -ef|grep snmpd|egrep -v \"grep\"\nvim /etc/snmp/snmpd.conf", recommendation6_3Str, result6_3DataStr, result6_3, "/", "/",
		}
		*xlsxData = append(*xlsxData, data6_3)
		//}
		// 6.4:检查是否禁止root用户远程登录
		*countAll++
		sshdConfigPath := "/etc/ssh/sshd_config"
		result6_4Data := make([]string, 0)
		recommendation6_4 := "/"
		result6_4 := "不合规"
		if StringTextScanner(startCommand(conn, "[[ -e \""+sshdConfigPath+"\" ]] && echo \"true\"")) == "true\n" {
			recommendation6_4 = `
执行备份：
cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config_bak
2、新建一个普通用户并设置高强度密码(防止设备上只存在root用户可用时，无法远程访问)：
useradd {username}
passwd {username}
3、禁止root用户远程登录系统
编辑文件/etc/ssh/sshd_config，修改PermitRootLogin值为no并去掉注释。
PermitRootLogin no
4、重启SSH服务
/etc/init.d/sshd restart`
			contents := StringTextScanner(startCommand(conn, "cat "+sshdConfigPath))
			for _, line := range strings.Split(contents, "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "#") && strings.Contains(line, "PermitRootLogin") {
					result6_4Data = append(result6_4Data, line)
					rootLoginSetting := strings.Split(line, " ")[1]
					if rootLoginSetting == "no" || rootLoginSetting == "NO" {
						result6_4 = "合规"
						recommendation6_4 = "/"
					} else {
						result6_4 = "不合规"
					}
				}
			}
		} else {
			result6_4 = "不合规"
			result6_4Data = append(result6_4Data, fmt.Sprintf("%s 不存在", sshdConfigPath))
			recommendation6_4 = fmt.Sprintf("%s 不存在，请检查ssh配置文件", sshdConfigPath)
		}
		if result6_4 == "合规" {
			//fmt.Println("6.4:检查是否禁止root用户远程登录\t合规")
			*countSuccess++
		} else {
			//fmt.Println("6.4:检查是否禁止root用户远程登录\t不合规")
			*countFail++
		}
		var result6_4Data_srt string
		if len(result6_4Data) > 0 {
			result6_4Data_srt = strings.Join(result6_4Data, "\n")
		} else {
			result6_4Data_srt = "未在 /etc/ssh/sshd_config 中找到 PermitRootLogin 配置"
		}
		data6_4 := []string{
			"6.4", "检查是否禁止root用户远程登录", "高危",
			"在SSH上不允许root登录，需要服务器管理员使用自己的帐户进行身份验证，然后通过sudo或su升级到根，这反过来限制了不可抵赖的机会，并在发生安全事件时提供了清晰的审计线索",
			"查看文件/etc/ssh/sshd_config，是否存在拒绝root用户通过SSH协议远程登录的配置", "PermitRootLogin no",
			"cat /etc/ssh/sshd_config | grep -v '#' | grep PermitRootLogin", recommendation6_4, result6_4Data_srt, result6_4, "/", "/",
		}
		*xlsxData = append(*xlsxData, data6_4)
	}

}

// 7
func His_Ntp_Cad(conn *ssh.Client, xlsxData *[][]string, countAll *int, countSuccess *int, countFail *int, count_manual *int) {

	// 7:其他配置
	// 7.1:检查系统openssh安全配置
	*countAll++
	sshdConfigPath := "/etc/ssh/sshd_config"
	result7_1 := "合规"
	result7_1Data := make([]string, 0)
	recommendation7_1 := make([]string, 0)

	if StringTextScanner(startCommand(conn, "[[ -e \""+sshdConfigPath+"\" ]] && echo \"true\"")) == "true\n" {
		cmd := "cat " + sshdConfigPath
		contents := StringTextScanner(startCommand(conn, cmd))
		flag7_1 := false
		for _, line := range strings.Split(contents, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "#") && strings.Contains(line, "X11Forwarding") {
				flag7_1 = true
				result7_1Data = append(result7_1Data, line)
				setting := strings.Split(line, " ")[1]
				if setting != "no" && setting != "NO" {
					result7_1 = "不合规"
					recommendation7_1 = append(recommendation7_1, "X11Forwarding no")
					break
				}
			}
		}
		if !flag7_1 {
			result7_1Data = append(result7_1Data, "X11Forwarding 被注释")
			recommendation7_1 = append(recommendation7_1, "X11Forwarding no")
		}
		flag7_1 = false
		for _, line := range strings.Split(contents, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "#") && strings.Contains(line, "MaxAuthTries") {
				flag7_1 = true
				result7_1Data = append(result7_1Data, line)
				if setting, err2 := strconv.Atoi(strings.Split(line, " ")[1]); err2 == nil {
					if setting > 5 {
						result7_1 = "不合规"
						recommendation7_1 = append(recommendation7_1, "MaxAuthTries 4")
						break
					}
				} else {
					result7_1 = "不合规"
					recommendation7_1 = append(recommendation7_1, "MaxAuthTries 4")
				}
			}
		}
		if !flag7_1 {
			result7_1Data = append(result7_1Data, "MaxAuthTries 被注释")
			recommendation7_1 = append(recommendation7_1, "MaxAuthTries 4")
		}
		flag7_1 = false
		for _, line := range strings.Split(contents, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "#") && strings.Contains(line, "IgnoreRhosts") {
				flag7_1 = true
				result7_1Data = append(result7_1Data, line)
				setting := strings.Split(line, " ")[1]
				if setting != "yes" && setting != "YES" {
					result7_1 = "不合规"
					recommendation7_1 = append(recommendation7_1, "IgnoreRhosts yes")
					break
				}
			}
		}
		if !flag7_1 {
			result7_1Data = append(result7_1Data, "IgnoreRhosts 被注释")
			recommendation7_1 = append(recommendation7_1, "IgnoreRhosts yes")
		}
		flag7_1 = false
		for _, line := range strings.Split(contents, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "#") && strings.Contains(line, "HostbasedAuthentication") {
				flag7_1 = true
				result7_1Data = append(result7_1Data, line)
				setting := strings.Split(line, " ")[1]
				if setting != "no" && setting != "NO" {
					result7_1 = "不合规"
					recommendation7_1 = append(recommendation7_1, "HostbasedAuthentication no")
					break
				}
			}
		}
		if !flag7_1 {
			result7_1Data = append(result7_1Data, "HostbasedAuthentication 被注释")
			recommendation7_1 = append(recommendation7_1, "HostbasedAuthentication no")
		}
		flag7_1 = false
		for _, line := range strings.Split(contents, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "#") && strings.Contains(line, "PermitEmptyPasswords") {
				flag7_1 = true
				result7_1Data = append(result7_1Data, line)
				setting := strings.Split(line, " ")[1]
				if setting != "no" && setting != "NO" {
					result7_1 = "不合规"
					recommendation7_1 = append(recommendation7_1, "PermitEmptyPasswords no")
					break
				}
			}
		}
		if !flag7_1 {
			result7_1Data = append(result7_1Data, "PermitEmptyPasswords 被注释")
			recommendation7_1 = append(recommendation7_1, "PermitEmptyPasswords no")
		}
		if result7_1 != "合规" {
			recommendation7_1 = []string{"编辑配置文件/etc/ssh/sshd_config,修改下面几个参数的值:\n" + strings.Join(recommendation7_1, "\n") + "\n重启ssh服务\n/etc/init.d/sshd restart"}
		} else {
			recommendation7_1 = []string{"/"}
		}
	} else {
		result7_1 = "不合规"
		result7_1Data = append(result7_1Data, fmt.Sprintf("%s 不存在", sshdConfigPath))
		recommendation7_1 = []string{fmt.Sprintf("%s 不存在，请检查ssh配置文件", sshdConfigPath)}
	}
	var result7_1Data_str string
	result7_1Data_str = strings.Join(result7_1Data, "\n")
	data7_1 := []string{
		"7.1", "检查系统openssh安全配置", "高危",
		"强烈建议系统放弃旧的明文登录协议，使用SSH防止会话劫持和嗅探网络上的敏感数据",
		"查看配置文件/etc/ssh/sshd_config,检查以下几个参数的配置值是否满足安全要求:\nX11Forwarding\tx11转发功能,如果没有需要使用此功能的应用应该关闭该功能\nMaxAuthTries\t指定每个连接允许的身份验证尝试的最大数量。建议配置为4次或者更少\nIgnoreRhosts\t此参数将强制用户在使用SSH进行身份验证时输入密码,建议开启开功能\nHostbasedAuthentication\t开启主机认证，建议关闭该功能\nPermitEmptyPasswords\t允许空密码登录，建议关闭该功能",
		"X11Forwarding no\nMaxAuthTries 4\nIgnoreRhosts yes\nHostbasedAuthentication no\nPermitEmptyPasswords no",
		"grep -v '#' /etc/ssh/sshd_config | grep -e X11Forwarding -e MaxAuthTries -e IgnoreRhosts -e HostbasedAuthentication -e PermitEmptyPasswords",
		strings.Join(recommendation7_1, "\n"), result7_1Data_str, result7_1, "/", "/",
	}
	*xlsxData = append(*xlsxData, data7_1)
	if result7_1 == "合规" {
		//fmt.Println("7.1:检查系统openssh安全配置\t合规")
		*countSuccess++
	} else {
		//fmt.Println("7.1:检查系统openssh安全配置\t不合规")
		*countFail++
	}

	// 7.2:检查是否禁止匿名用户登录FTP
	*countAll++
	var result7_2 string
	result7_2Data := make([]string, 0)
	recommendation7_2 := make([]string, 0)
	anonymousEnable := false
	ftpCheckCommand := "bash -c ps -ef | grep ftpd | grep -v grep | wc -l"
	ftpOutput := StringTextScanner(startCommand(conn, ftpCheckCommand))

	ftpStat := strings.TrimSpace(ftpOutput)
	ftpConfig := "/"
	if ftpStat == "0" {
		result7_2Data = append(result7_2Data, "FTP进程不存在")
		result7_2 = "合规"
		*countSuccess++
	} else {
		result7_2Data = append(result7_2Data, "FTP进程已启动")
		if StringTextScanner(startCommand(conn, "[[ -e \"/etc/vsftpd.conf\" ]] && echo \"true\"")) == "true\n" {
			ftpConfig = "/etc/vsftpd.conf"
		} else if StringTextScanner(startCommand(conn, "[[ -e \"/etc/vsftpd/vsftpd.conf\" ]] && echo \"true\"")) == "true\n" {
			ftpConfig = "/etc/vsftpd/vsftpd.conf"
		} else {
			result7_2Data = append(result7_2Data, "FTP 配置文件未找到")
			recommendation7_2 = append(recommendation7_2, "FTP 配置文件未找到，人工检查")
		}
		if ftpConfig != "/" {
			contents := StringTextScanner(startCommand(conn, "cat "+ftpConfig))
			for _, line := range strings.Split(contents, "\n") {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "anonymous_enable=") {
					result7_2Data = append(result7_2Data, line)
					if strings.Split(line, "=")[1] == "yes" || strings.Split(line, "=")[1] == "YES" {
						anonymousEnable = true
						recommendation7_2 = append(recommendation7_2, fmt.Sprintf("编辑文件%s,修改参数anonymous_enable的值为NO：\nanonymous_enable=NO\n重启FTP服务", ftpConfig))
					}
				}
			}
		}

		if anonymousEnable {
			result7_2 = "合规"
		} else {
			result7_2 = "不合规"
		}
	}
	if result7_2 == "合规" {
		*countSuccess++
		recommendation7_2 = append(recommendation7_2, "/")
		//fmt.Println("7.2:检查是否禁止匿名用户登录FTP\t合规")
	} else {
		*countFail++
		//fmt.Println("7.2:检查是否禁止匿名用户登录FTP\t不合规")
	}
	data7_2 := []string{
		"7.2",
		"检查是否禁止匿名用户登录",
		"高危",
		"禁止匿名用户登录FTP服务器。",
		"/",
		"未启用FTP服务或禁止匿名用户登录FTP服务",
		fmt.Sprintf("ps -ef | grep ftpd | grep -v grep\n cat {%s} | grep anonymous_enable", ftpConfig),
		strings.Join(recommendation7_2, "\n"),
		strings.Join(result7_2Data, "\n"),
		result7_2,
		"/",
		"/",
	}
	*xlsxData = append(*xlsxData, data7_2)

	//fileList := []string{".rhost", ".netrc", "hosts.equiv"}
	*countAll++
	result7_3Data := []string{}
	recommendation7_3 := []string{}
	existFileList := []string{}
	var result7_3 string
	cmd := "find / \\( -path '/run/user/*' -o -path '/proc/*' -o -path '/sys/*' -o -path '/dev/*' \\) -prune -o -name .rhost -print && find / \\( -path '/run/user/*' -o -path '/proc/*' -o -path '/sys/*' -o -path '/dev/*' \\) -prune -o -name .netrc -print && find / \\( -path '/run/user/*' -o -path '/proc/*' -o -path '/sys/*' -o -path '/dev/*' \\) -prune -o -name hosts.equiv -print"
	//fileResults := StringTextScanner(startCommand(conn, "find / -name .rhost && find / -name .netrc && find / -name hosts.equiv"))
	fileResults := StringTextScanner(startCommand(conn, cmd))
	if fileResults != "/" {
		for _, line := range strings.Split(fileResults, "\n") {
			if line != "/" && line != "" && !strings.Contains(line, "No such file or directory") {
				existFileList = append(existFileList, strings.TrimSpace(line))
			}
		}
	}

	if len(existFileList) == 0 {
		result7_3 = "合规"
		*countSuccess++
		existFileList = append(existFileList, "/")
		recommendation7_3 = append(recommendation7_3, "/")
		result7_3Data = append(result7_3Data, "不存在如下文件：\".rhost .netrc hosts.equiv\"")
		//fmt.Println("7.3:检查是否删除了潜在危险文件\t合规")
	} else {
		result7_3 = "不合规"
		*countFail++
		//fmt.Println("7.3:检查是否删除了潜在危险文件\t不合规")
		result7_3Data = existFileList
		recommendation7_3 = []string{"使用rm命令删除以下文件：\n" + strings.Join(existFileList, "\n")}
	}

	data7_3 := []string{
		"7.3",
		"检查是否删除了潜在危险文件",
		"高危",
		".rhosts，.netrc，hosts.equiv等文件都具有潜在的危险，如果没有应用，应该删除",
		"使用find 或 locate命令查看系统是否存在如下文件：\".rhost .netrc hosts.equiv\"",
		"不存在如下文件：\".rhost .netrc hosts.equiv\"",
		"find / -name .rhost && find / -name .netrc&&find / -name hosts.equiv\nupdatedb\nlocate hosts.equiv|grep -i \"hosts.equiv$\"\nlocate .netrc|grep -i \".netrc$\"\nlocate .rhost|grep -i \".rhost$\"/",
		strings.Join(recommendation7_3, "\n"),
		strings.Join(result7_3Data, "\n"),
		result7_3,
		"/",
		"/",
	}
	*xlsxData = append(*xlsxData, data7_3)

	*countAll++
	data7_4Date := []string{}
	profilePath := "/etc/profile"
	recommendation7_4 := []string{}
	cmd = "cat" + profilePath
	profile := startCommand(conn, cmd)

	scanner := bufio.NewScanner(profile)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") && strings.Contains(line, "TMOUT") {
			data7_4Date = append(data7_4Date, line)
		}
	}

	flag7_4_1 := false
	flag7_4_2 := false
	var result7_4 string
	if len(data7_4Date) > 0 {
		for _, line := range data7_4Date {
			if strings.Contains(line, "=") {
				value, err1 := strconv.Atoi(strings.Split(line, "=")[1])
				if err1 == nil && value <= 300 {
					flag7_4_1 = true
				}
			}
			if strings.Contains(line, "export") {
				flag7_4_2 = true
			}
		}
		data7_4Date = []string{strings.Join(data7_4Date, "\n")}

		if flag7_4_1 && flag7_4_2 {
			result7_4 = "合规"
			recommendation7_4 = []string{"/"}
		} else if flag7_4_1 && !flag7_4_2 {
			result7_4 = "不合规"
			recommendation7_4 = []string{"export TMOUT"}
		} else if !flag7_4_1 && flag7_4_2 {
			result7_4 = "不合规"
			recommendation7_4 = []string{"TMOUT=300"}
		} else {
			result7_4 = "不合规"
			recommendation7_4 = []string{"TMOUT=300", "export TMOUT"}
		}
	} else {
		line := "未配置"
		data7_4Date = []string{}
		data7_4Date = append(data7_4Date, line)
		result7_4 = "不合规"
		recommendation7_4 = []string{"TMOUT=300", "export TMOUT"}
	}

	if len(recommendation7_4) > 0 {
		recommendation7_4 = []string{strings.Join(recommendation7_4, "\n")}
		recommendation7_4 = []string{"执行备份\ncp -p /etc/profile /etc/profile_bak\n在/etc/profile文件中增加如下行(存在则修改，不存在则添加)：\n" + strings.Join(recommendation7_4, "\n\n") + "\n执行以下命令使TMOUT参数立即生效\nsource /etc/profile"}
	}

	if result7_4 == "合规" {
		*countSuccess++
		//fmt.Println("7.4:检查是否设置命令行界面超时退出\t合规")
	} else {
		*countFail++
		//fmt.Println("7.4:检查是否设置命令行界面超时退出\t不合规")
	}

	data7_4 := []string{
		"7.4", "检查是否设置命令行界面超时退出", "高危", "对于具备字符交互界面的设备，应配置定时帐户自动登出，避免管理员忘记注销登录，减少安全隐患。", "查看/etc/profile文件中是否配置超时设置", "设置命令行界面登录后300s内无任何操作自动登出\nTMOUT=300\nexport TMOUT",
		"cat /etc/profile |grep -i TMOUT", strings.Join(recommendation7_4, "\n"), strings.Join(data7_4Date, "\n"), result7_4, "/", "/",
	}
	*xlsxData = append(*xlsxData, data7_4)

	*countAll++
	var result7_5 string
	var profilePath7_5 []string
	result7_5Data := []string{}
	recommendation7_5 := "/"
	if StringTextScanner(startCommand(conn, "[[ -e \"/root/.bash_profile\" ]] && echo \"true\"")) == "true\n" {
		profilePath7_5 = append(profilePath7_5, "/root/.bash_profile")
	}
	if StringTextScanner(startCommand(conn, "[[ -e \"/etc/profile\" ]] && echo \"true\"")) == "true\n" {
		profilePath7_5 = append(profilePath7_5, "/etc/profile")
	}
	paths := StringTextScanner(startCommand(conn, "echo $PATH"))
	for _, path := range strings.Split(paths, ":") {
		if path == "." || path == "./" || path == ".." || path == "../" {
			result7_5Data = append(result7_5Data, path)
		}
	}

	if len(result7_5Data) == 0 {
		result7_5Data = []string{"/"}
		result7_5 = "合规"
		*countSuccess++
		//fmt.Println("7.5:检查root用户的path环境变量\t合规")
	} else {
		result7_5Data = []string{strings.Join(result7_5Data, "\n")}
		result7_5 = "不合规"
		*countFail++
		//fmt.Println("7.5:检查root用户的path环境变量\t不合规")
		if len(profilePath7_5) > 0 {
			recommendation7_5 = "修改文件 " + strings.Join(profilePath7_5, " 或 ") + " 中的环境变量$PATH，删除环境变量值包含的（.和..）的路径"
		} else {
			recommendation7_5 = "配置文件未找到，请人工检查环境变量$PATH，删除环境变量值包含的（.和..）的路径"
		}
	}

	data7_5 := []string{
		"7.5", "检查root用户的path环境变量", "中危", "root用户环境变量的安全性", "使用命令echo $PATH查看PATH环境变量的值，确认PATH环境变量中是否存在.或者..的路径", "$PATH环境变量中不存在.或者..的路径则合规，否则不合规", "echo $PATH",
		recommendation7_5, strings.Join(result7_5Data, "\n"), result7_5, "/", "/",
	}
	*xlsxData = append(*xlsxData, data7_5)

	*countAll++
	result7_6Data := []string{}
	profilePathList := []string{"/etc/profile", "~/.bashrc", "~/.bash_history", "/etc/bashrc", "/etc/profile.d/", "~/.inputrc", "~/.bash_login", "/etc/bash.bashrc", "~/.profile"}
	result7_6 := "不合规"
	recommendation7_6 := []string{}
	HISTFILESIZE_flag := false
	HISTSIZE_flag := false
	HISTFILESIZE := new(int)
	HISTSIZE := new(int)
	*HISTFILESIZE = 0
	*HISTSIZE = 0
	filePath := ""

	boolValue := false
	for _, profilePath = range profilePathList {
		if !boolValue {
			if strings.HasPrefix(profilePath, "~") {
				boolValue, filePath = readUser(strings.Split(profilePath, "/")[1], result7_6Data, HISTFILESIZE, HISTSIZE, conn)
			} else {
				profile = startCommand(conn, "cat "+profilePath)
				boolValue = checkHistoryFile(profile, result7_6Data, HISTFILESIZE, HISTSIZE)
				if boolValue {
					filePath = profilePath
				}

			}
		}
	}

	if *HISTFILESIZE <= 5 {
		HISTFILESIZE_flag = true
	} else {
		recommendation7_6 = append(recommendation7_6, "HISTFILESIZE=5")
	}
	if *HISTSIZE <= 5 {
		HISTSIZE_flag = true
	} else {
		recommendation7_6 = append(recommendation7_6, "HISTSIZE=5")
	}

	if HISTFILESIZE_flag && HISTSIZE_flag {
		result7_6 = "合规"
		*countSuccess++
		resultData := fmt.Sprintf("HISTFILESIZE 为：%s  \n HISTSIZE 为：%s \n 所在文件位置为：%s", strconv.Itoa(*HISTFILESIZE), strconv.Itoa(*HISTSIZE), filePath)
		result7_6Data = []string{resultData}
		//fmt.Println("7.6:检查历史命令设置\t合规")
	} else {
		result7_6 = "不合规"
		*countFail++
		//fmt.Println("7.6:检查历史命令设置\t不合规")
		recommendation7_6 = []string{"编辑文件/etc/profile，在文件中加入如下两行(存在则修改)：\n" + strings.Join(recommendation7_6, "\n")}
		resultData := fmt.Sprintf("HISTFILESIZE 为：%s  \n HISTSIZE 为：%s \n 所在文件位置为：%s", strconv.Itoa(*HISTFILESIZE), strconv.Itoa(*HISTSIZE), filePath)
		result7_6Data = []string{resultData}
		recommendation7_6 = []string{"编辑文件/etc/profile，在文件中加入如下两行(存在则修改)：\n" + strings.Join(recommendation7_6, "\n")}
	}

	if len(result7_6Data) == 0 {
		result7_6Data = []string{strings.Join(result7_6Data, "\n")}
	} else {
		result7_6Data = []string{strings.Join(result7_6Data, "\n")}
	}

	data7_6 := []string{
		"7.6", "检查历史命令设置", "中危", "保证bash shell保存少量的（或不保存）命令，保存较少的命令条数，减少安全隐患。", "编辑文件/etc/profile查看是否存在如下内容：\nHISTFILESIZE=5\nHISTSIZE=5", "HISTFILESIZE和HISTSIZE的值小于等于5则合规，否则不合规。", "cat /etc/profile | grep -v '#' | awk '/HISTFILESIZE/ || /HISTSIZE/'",
		strings.Join(recommendation7_6, "\n"), strings.Join(result7_6Data, "\n"), result7_6, "/", "/",
	}
	*xlsxData = append(*xlsxData, data7_6)

	*countAll++
	result7_7Data := "/"
	recommendation7_7 := "/"
	var result7_7 string
	ctrlAltDelPath := "/usr/lib/systemd/system/ctrl-alt-del.target"
	if StringTextScanner(startCommand(conn, "[[ -e \""+ctrlAltDelPath+"\" ]] && echo \"true\"")) != "ture\n" {
		recommendation7_7 = "未定位到ctrl-alt-del.target，人工检查"
	} else {
		scanner = bufio.NewScanner(startCommand(conn, "cat "+ctrlAltDelPath))
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "#") && strings.Contains(line, "Alias") && strings.Contains(line, "ctrl-alt-del.target") {
				result7_7Data = line
				recommendation7_7 = "编辑文件/usr/lib/systemd/system/ctrl-alt-del.target,将如下行删除或注释:\nAlias=ctrl-alt-del.target"
			}
		}

	}

	if result7_7Data == "/" {
		result7_7 = "合规"
		*countSuccess++
		//fmt.Println("7.7:检查系统是否禁用Ctrl+Alt+Delete组合键\t合规")
	} else {
		result7_7 = "不合规"
		*countFail++
		//fmt.Println("7.7:检查系统是否禁用Ctrl+Alt+Delete组合键\t不合规")
	}

	data7_7 := []string{
		"7.7", "检查系统是否禁用Ctrl+Alt+Delete组合键", "中危", "禁止Ctrl+Alt+Delete，防止非法重新启动服务器。",
		"查看文件/usr/lib/systemd/system/ctrl-alt-del.target,是否存在使用组合键Ctrl+Alt+Delete控制系统重启的配置。\nAlias=ctrl-alt-del.target",
		"禁用了使用组合键Ctrl+Alt+Delete重启系统则合规,否则不合规。", "cat /usr/lib/systemd/system/ctrl-alt-del.target | grep Alias | grep -v '#'",
		recommendation7_7, result7_7Data, result7_7, "/", "/",
	}
	*xlsxData = append(*xlsxData, data7_7)

	*countAll++
	result7_8Data := []string{}
	ntpRunning := false
	var result7_8 string
	ntpCheckCommand := []string{}
	ntpServices := map[string]string{
		"systemd-timesyncd.service": "/etc/systemd/timesyncd.conf",
		"systemd-timesyncd":         "/etc/systemd/timesyncd.conf",
		"chronyd":                   "/etc/chrony.conf",
		"ntpd":                      "/etc/ntp.conf",
		"ntp":                       "/etc/ntp.conf",
	}
	for ntpService, configFile := range ntpServices {
		ntpCheckCommand = append(ntpCheckCommand, fmt.Sprintf("service status %s", ntpService)+"\n"+fmt.Sprintf("systemctl status %s", ntpService))
		if checkCommand(conn, ntpService) || checkNtpTime(conn, ntpService) {
			ntpRunning = true
			result7_8Data = append(result7_8Data, fmt.Sprintf("%s 已启动", ntpService))
			if configFile == "/etc/systemd/timesyncd.conf" {
				if StringTextScanner(startCommand(conn, "[[ -e \""+configFile+"\" ]] && echo \"true\"")) == "true\n" {
					result7_8Data = append(result7_8Data, "时间同步服务器设置为：")
					ntpServer := "/"
					profile4 := startCommand(conn, "cat "+configFile)
					scanner = bufio.NewScanner(profile4)
					for scanner.Scan() {
						line := scanner.Text()
						line = strings.TrimSpace(line)
						if !strings.HasPrefix(line, "#") && strings.Contains(line, "NTP") {
							ntpServer = strings.Split(line, "=")[1]
							result7_8Data = append(result7_8Data, ntpServer)
						}
					}

					if ntpServer == "/" {
						result7_8Data = append(result7_8Data, "未找到时间同步服务器")
					}
				} else {
					result7_8Data = append(result7_8Data, fmt.Sprintf("配置文件 %s 未找到", configFile))
				}
			} else {
				if StringTextScanner(startCommand(conn, "[[ -e \""+configFile+"\" ]] && echo \"true\"")) == "true\n" {
					result7_8Data = append(result7_8Data, "时间同步服务器设置为：")
					ntpServer := "/"
					profile5 := startCommand(conn, "cat "+configFile)
					scanner = bufio.NewScanner(profile5)
					for scanner.Scan() {
						line := scanner.Text()
						line = strings.TrimSpace(line)
						if !strings.HasPrefix(line, "#") && strings.Contains(line, "NTP") {
							ntpServer = strings.Split(strings.TrimSpace(line), "=")[1]
							result7_8Data = append(result7_8Data, ntpServer)
						}
					}

					if ntpServer == "/" {
						result7_8Data = append(result7_8Data, "未找到时间同步服务器")
					}
				} else {
					result7_8Data = append(result7_8Data, fmt.Sprintf("配置文件 %s 未找到", configFile))
				}
			}
		}
	}

	if ntpRunning {
		result7_8 = "人工判断"
		*count_manual++
		//fmt.Println("7.8:检查是否使用NTP保持时间同步\t合规")
	} else {
		result7_8 = "不合规"
		*countFail++
		//fmt.Println("7.8:检查是否使用NTP保持时间同步\t不合规")
	}

	ntpCheckCommand = []string{strings.Join(ntpCheckCommand, "\n")}
	if len(result7_8Data) > 0 {
		result7_8Data = []string{strings.Join(result7_8Data, "\n")}
	} else {
		result7_8Data = []string{}
	}

	data7_8 := []string{
		"7.8", "检查是否使用NTP保持时间同步", "低危", "建议将缺乏直接访问物理主机时钟的物理系统和虚拟客户机配置为NTP客户机来同步它们的时钟(特别是支持像Kerberos这样的时间敏感安全机制)。这也确保日志文件在整个企业中都有一致的时间记录,这有助于问题排查。",
		fmt.Sprintf("检查%s服务是否启动", getKey(ntpServices, " 或 ")), "NTP服务处于开启状态", strings.Join(ntpCheckCommand, "\n"), "开启NTP服务，并查看是否配置NTP服务器", strings.Join(result7_8Data, "\n"), result7_8, "/", "/",
	}
	*xlsxData = append(*xlsxData, data7_8)

	var result7_9 string
	var result7_9_data string
	hostsAllowPath := "/etc/hosts.allow"
	hostsDenyPath := "/etc/hosts.deny"
	hostsAllow := []string{}
	hostsDeny := []string{}
	*countAll++
	fileExisAllow := false
	fileExisDeny := false
	if StringTextScanner(startCommand(conn, "[[ -e \""+hostsAllowPath+"\" ]] && echo \"true\"")) == "true\n" {
		fileExisAllow = true
		scanner = bufio.NewScanner(startCommand(conn, "cat "+hostsAllowPath))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "/" && !strings.HasPrefix(line, "#") {
				hostsAllow = append(hostsAllow, line)
			}
		}
	} else {
		hostsAllow = append(hostsAllow, fmt.Sprintf("%s 文件不存在", hostsAllow))
	}
	if StringTextScanner(startCommand(conn, "[[ -e \""+hostsDenyPath+"\" ]] && echo \"true\"")) == "true\n" {
		fileExisDeny = true
		file := startCommand(conn, "cat "+hostsDenyPath)
		scanner = bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "/" && !strings.HasPrefix(line, "#") {
				hostsDeny = append(hostsDeny, line)
			}
		}
	} else {
		hostsAllow = append(hostsAllow, fmt.Sprintf("%s 文件不存在", hostsDenyPath))
	}
	if len(hostsAllow) == 0 && len(hostsDeny) == 0 {
		result7_9 = "不合规"
		result7_9_data = "未限制访问IP"
		*countFail++
	} else if !fileExisDeny && !fileExisAllow {
		result7_9 = "不合规"
		result7_9_data = strings.Join(hostsAllow, "\n")
		*countFail++
	} else if !fileExisDeny || !fileExisAllow {
		result7_9 = "人工判断"
		if !fileExisDeny {
			result7_9_data = strings.Join(hostsDeny, "\n")
			result7_9_data = "允许：" + strings.Join(hostsAllow, "\n")
		}
		if !fileExisAllow {
			result7_9_data = strings.Join(hostsAllow, "\n")
			result7_9_data = "不允许：" + strings.Join(hostsDeny, "\n")
		}
		*count_manual++
	} else if len(hostsAllow) > 0 && len(hostsDeny) == 0 {
		result7_9 = "人工判断"
		result7_9_data = "允许：" + strings.Join(hostsAllow, "\n")
		*count_manual++
	} else if len(hostsDeny) > 0 && len(hostsAllow) == 0 {
		result7_9 = "人工判断"
		result7_9_data = "不允许：" + strings.Join(hostsDeny, "\n")
		*count_manual++
	} else {
		result7_9 = "人工判断"
		result7_9_data = "允许：" + strings.Join(hostsAllow, "\n") + "\n不允许：" + strings.Join(hostsDeny, "\n")
		*count_manual++
	}

	data7_9 := []string{
		"7.9", "检查是否限制访问IP", "低危", "应限制访问主机的IP", "检查允许的IP\n/etc/hosts.allow\n检查不允许的IP\n/etc/hosts.deny", "根据企业要求", "cat /etc/hosts.allow | grep -v '#' | grep allow\ncat /etc/hosts.deny | grep -v '#'", "根据企业要求修改文件", result7_9_data, result7_9, "/", "/",
	}
	*xlsxData = append(*xlsxData, data7_9)
}
