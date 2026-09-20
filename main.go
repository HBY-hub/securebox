package main

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	magic      = "SBOX1"
	saltSize   = 16
	nonceSize  = 12
	iterations = 390000
	defaultMB  = 35
)

type partManifest struct {
	SourceName string `json:"source_name"`
	PartCount  int    `json:"part_count"`
	SHA256     string `json:"sha256"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	var err error
	switch os.Args[1] {
	case "encrypt", "decrypt", "encode", "decode":
		err = transform(os.Args[1], os.Args[2:])
	case "zip":
		err = createZip(os.Args[2:])
	case "unzip":
		err = extractZip(os.Args[2:])
	case "split":
		err = split(os.Args[2:])
	case "join":
		err = join(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		err = fmt.Errorf("未知命令：%s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`SecureBox - 加密、Base64、ZIP 与分片工具

用法（选项与目标文件顺序任意，-out、-password 也可写成 --out=... 形式）：
  securebox encrypt [-password 密码] [-out 输出文件] <输入文件>
  securebox decrypt [-password 密码] [-out 输出文件] <输入文件>
  securebox encode  [-out 输出文件] <输入文件>
  securebox decode  [-out 输出文件] <输入文件>
  securebox zip     [-out 输出文件] <文件或文件夹>
  securebox unzip   [-out 输出文件夹] <zip文件>
  securebox split   [-size 35] <输入文件>
  securebox join    <.part001 文件>
  securebox <命令> [选项...] -- <目标文件>   （-- 之后全部视为目标文件）

未指定 -out 时，结果保存到 Downloads。split 默认每片 35 MB。
密码也可通过 SECUREBOX_PASSWORD 环境变量传入；命令行参数可能被系统记录，不建议长期使用 -password。
`)
}

func downloads() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		if profile := os.Getenv("USERPROFILE"); profile != "" {
			home = profile
		}
	}
	dir := filepath.Join(home, "Downloads")
	return dir, os.MkdirAll(dir, 0755)
}

func defaultOutput(name string) (string, error) {
	dir, err := downloads()
	if err != nil {
		return "", err
	}
	return available(filepath.Join(dir, name))
}

func available(path string) (string, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return path, nil
	}
	if err != nil {
		return "", err
	}
	ext, suffix := filepath.Ext(path), 1
	base := strings.TrimSuffix(path, ext)
	for ; suffix < 1000; suffix++ {
		candidate := fmt.Sprintf("%s_%d%s", base, suffix, ext)
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
	}
	return "", errors.New("无法生成不重复的输出文件名")
}

// cliArgs 保存解析后的命令行：位置参数与选项可以任意混排。
type cliArgs struct {
	positional []string
	flags      map[string]string
}

// parseCLI 解析参数，支持：
//   -flag value、-flag=value、--flag value、--flag=value
//
// 位置参数允许出现在选项之前、之后或中间；单独的 "-" 视为普通参数；
// "--" 之后的所有内容全部按位置参数处理（便于处理以 - 开头的文件名）。
func parseCLI(args []string) (*cliArgs, error) {
	c := &cliArgs{flags: map[string]string{}}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			c.positional = append(c.positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			name := strings.TrimLeft(arg, "-")
			if name == "" {
				c.positional = append(c.positional, arg)
				continue
			}
			value := ""
			if eq := strings.Index(name, "="); eq >= 0 {
				value = name[eq+1:]
				name = name[:eq]
			} else if i+1 < len(args) {
				value = args[i+1]
				i++
			} else {
				return nil, fmt.Errorf("选项 -%s 缺少值", name)
			}
			c.flags[name] = value
			continue
		}
		c.positional = append(c.positional, arg)
	}
	return c, nil
}

// requireFlags 校验只允许出现的选项名；多余的选项视为错误，避免拼写错误被静默忽略。
func (c *cliArgs) requireFlags(allowed ...string) error {
	for name := range c.flags {
		ok := false
		for _, a := range allowed {
			if name == a {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("未知选项：-%s", name)
		}
	}
	return nil
}

// singlePositional 校验位置参数个数，返回唯一的目标文件。
func (c *cliArgs) singlePositional(what string) (string, error) {
	if len(c.positional) != 1 {
		return "", fmt.Errorf("需要一个%s", what)
	}
	return c.positional[0], nil
}

// parseInputOut 解析 encrypt/decrypt/encode/decode 的参数。
func parseInputOut(command string, args []string) (string, string, string, error) {
	c, err := parseCLI(args)
	if err != nil {
		return "", "", "", err
	}
	if err := c.requireFlags("out", "password"); err != nil {
		return "", "", "", err
	}
	input, err := c.singlePositional("输入文件")
	if err != nil {
		return "", "", "", err
	}
	return input, c.flags["out"], c.flags["password"], nil
}

func transform(command string, args []string) error {
	input, output, suppliedPassword, err := parseInputOut(command, args)
	if err != nil {
		return err
	}
	if output == "" {
		switch command {
		case "encrypt":
			output, err = defaultOutput(filepath.Base(input) + ".sbox")
		case "decrypt", "decode":
			output, err = defaultOutput(strings.TrimSuffix(filepath.Base(input), filepath.Ext(input)))
		case "encode":
			output, err = defaultOutput(filepath.Base(input) + ".b64")
		}
		if err != nil {
			return err
		}
	}
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	var result []byte
	switch command {
	case "encrypt":
		result, err = encrypt(data, getPassword(suppliedPassword))
	case "decrypt":
		result, err = decrypt(data, getPassword(suppliedPassword))
	case "encode":
		result = []byte(base64.StdEncoding.EncodeToString(data))
	case "decode":
		result, err = base64.StdEncoding.DecodeString(string(data))
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, result, 0600); err != nil {
		return err
	}
	fmt.Println(output)
	return nil
}

func getPassword(supplied string) string {
	if supplied != "" {
		return supplied
	}
	return os.Getenv("SECUREBOX_PASSWORD")
}

func encrypt(data []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("需要密码，请使用 -password 或 SECUREBOX_PASSWORD")
	}
	salt, nonce := make([]byte, saltSize), make([]byte, nonceSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := append([]byte(magic), byte((iterations>>24)&0xff), byte((iterations>>16)&0xff), byte((iterations>>8)&0xff), byte(iterations&0xff))
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return append(append(append(header, salt...), nonce...), gcm.Seal(nil, nonce, data, append(append(header, salt...), nonce...))...), nil
}

func decrypt(blob []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("需要密码，请使用 -password 或 SECUREBOX_PASSWORD")
	}
	if len(blob) < len(magic)+4+saltSize+nonceSize+16 || string(blob[:len(magic)]) != magic {
		return nil, errors.New("不是 SecureBox 加密文件或文件已损坏")
	}
	offset := len(magic)
	rounds := int(blob[offset])<<24 | int(blob[offset+1])<<16 | int(blob[offset+2])<<8 | int(blob[offset+3])
	if rounds < 100000 || rounds > 10000000 {
		return nil, errors.New("加密文件参数无效")
	}
	offset += 4
	salt := blob[offset : offset+saltSize]
	offset += saltSize
	nonce := blob[offset : offset+nonceSize]
	offset += nonceSize
	header := blob[:len(magic)+4]
	key, err := pbkdf2.Key(sha256.New, password, salt, rounds, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, blob[offset:], append(append(header, salt...), nonce...))
}

func createZip(args []string) error {
	c, err := parseCLI(args)
	if err != nil {
		return err
	}
	if err := c.requireFlags("out"); err != nil {
		return err
	}
	input, err := c.singlePositional("文件或文件夹")
	if err != nil {
		return err
	}
	out := c.flags["out"]
	if out == "" {
		out, err = defaultOutput(filepath.Base(input) + ".zip")
		if err != nil {
			return err
		}
	}
	target, err := os.Create(out)
	if err != nil {
		return err
	}
	defer target.Close()
	archive := zip.NewWriter(target)
	defer archive.Close()
	info, err := os.Stat(input)
	if err != nil {
		return err
	}
	root := filepath.Dir(input)
	if !info.IsDir() {
		return zipOne(archive, input, filepath.Base(input))
	}
	return filepath.Walk(input, func(path string, walkInfo os.FileInfo, walkErr error) error {
		if walkErr != nil || walkInfo.IsDir() {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		return zipOne(archive, path, rel)
	})
}

func zipOne(archive *zip.Writer, path, name string) error {
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer source.Close()
	writer, err := archive.Create(filepath.ToSlash(name))
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, source)
	return err
}

func extractZip(args []string) error {
	c, err := parseCLI(args)
	if err != nil {
		return err
	}
	if err := c.requireFlags("out"); err != nil {
		return err
	}
	input, err := c.singlePositional("ZIP 文件")
	if err != nil {
		return err
	}
	out := c.flags["out"]
	if out == "" {
		out, err = defaultOutput(strings.TrimSuffix(filepath.Base(input), filepath.Ext(input)))
		if err != nil {
			return err
		}
	}
	archive, err := zip.OpenReader(input)
	if err != nil {
		return err
	}
	defer archive.Close()
	for _, item := range archive.File {
		target := filepath.Join(out, item.Name)
		clean := filepath.Clean(target)
		if clean != filepath.Clean(out) && !strings.HasPrefix(clean, filepath.Clean(out)+string(os.PathSeparator)) {
			return errors.New("ZIP 包含不安全路径")
		}
		if item.FileInfo().IsDir() {
			if err := os.MkdirAll(clean, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(clean), 0755); err != nil {
			return err
		}
		source, err := item.Open()
		if err != nil {
			return err
		}
		targetFile, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, item.Mode())
		if err != nil {
			source.Close()
			return err
		}
		_, copyErr := io.Copy(targetFile, source)
		targetFile.Close()
		source.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	fmt.Println(out)
	return nil
}

func split(args []string) error {
	c, err := parseCLI(args)
	if err != nil {
		return err
	}
	if err := c.requireFlags("size"); err != nil {
		return err
	}
	input, err := c.singlePositional("输入文件")
	if err != nil {
		return err
	}
	size := defaultMB
	if raw, ok := c.flags["size"]; ok && raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &size); err != nil || size <= 0 {
			return errors.New("分片大小必须是大于 0 的整数（MB）")
		}
	}
	info, err := os.Stat(input)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("分片输入必须是文件")
	}
	dir, err := downloads()
	if err != nil {
		return err
	}
	chunk := int64(size) * 1024 * 1024
	count := int((info.Size() + chunk - 1) / chunk)
	if count == 0 {
		count = 1
	}
	base := filepath.Base(input)
	for i := 1; i <= count; i++ {
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("%s.part%03d", base, i))); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("分片已存在：%s", filepath.Join(dir, fmt.Sprintf("%s.part%03d", base, i)))
		}
	}
	source, err := os.Open(input)
	if err != nil {
		return err
	}
	defer source.Close()
	hash := sha256.New()
	reader := io.TeeReader(source, hash)
	for i := 1; i <= count; i++ {
		target, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s.part%03d", base, i)))
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(target, reader, chunk)
		target.Close()
		if copyErr != nil && !errors.Is(copyErr, io.EOF) {
			return copyErr
		}
	}
	manifest := partManifest{SourceName: base, PartCount: count, SHA256: fmt.Sprintf("%x", hash.Sum(nil))}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(dir, base+".parts.json")
	if err := os.WriteFile(manifestPath, data, 0600); err != nil {
		return err
	}
	fmt.Printf("已创建 %d 个分片和清单：%s\n", count, manifestPath)
	return nil
}

func join(args []string) error {
	c, err := parseCLI(args)
	if err != nil {
		return err
	}
	if err := c.requireFlags(); err != nil {
		return err
	}
	first, err := c.singlePositional(".part001 文件")
	if err != nil {
		return err
	}
	name := filepath.Base(first)
	if !strings.HasSuffix(name, ".part001") {
		return errors.New("请选择 .part001 文件")
	}
	base := strings.TrimSuffix(name, ".part001")
	data, err := os.ReadFile(filepath.Join(filepath.Dir(first), base+".parts.json"))
	if err != nil {
		return errors.New("缺少 .parts.json 清单，请将它与所有分片放在同一文件夹")
	}
	var manifest partManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	if manifest.SourceName != base || manifest.PartCount < 1 {
		return errors.New("分片清单无效")
	}
	out, err := defaultOutput(base)
	if err != nil {
		return err
	}
	temporary := out + ".partial"
	target, err := os.Create(temporary)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	hash := sha256.New()
	for i := 1; i <= manifest.PartCount; i++ {
		part := filepath.Join(filepath.Dir(first), fmt.Sprintf("%s.part%03d", base, i))
		source, err := os.Open(part)
		if err != nil {
			target.Close()
			return fmt.Errorf("缺少分片：%s", part)
		}
		_, copyErr := io.Copy(io.MultiWriter(target, hash), source)
		source.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != manifest.SHA256 {
		target.Close()
		return errors.New("分片校验失败，文件可能损坏")
	}
	if err := target.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, out); err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}
