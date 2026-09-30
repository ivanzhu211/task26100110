# VaultBrowse JPEG EXIF 清洗组件

## 接口

```go
func ScrubJPEG(src io.Reader, dstPath string) error
```

- `src`：上游从嵌入图片解出的 JPEG 字节流（8 位基线或渐进式，支持多 SOS 扫描）。
- `dstPath`：清洗结果的本地输出路径。

成功后，`dstPath` 中的内容是输入删除所有 EXIF 段后的字节序列：

- 删除所有 payload 以 `Exif\x00\x00` 开头的 APP1 段（含标记、长度字段与完整 payload），不解析 TIFF，TIFF 损坏也照常删除；EXIF 段可出现在任意位置、可出现多次（首个扫描前、扫描之间、最后一次扫描之后）。
- 其余字节逐字节保留：非 EXIF 的 APP1、ICC（APP2）、注释、压缩图像数据、段标记前的 FF 填充、扫描数据中的 FF00 填塞与 RST0–RST7 重启标记、EOI 之后的尾随字节。
- 输入不是合法 JPEG 结构（缺 SOI、段长度越界等）时返回错误，且不产生输出文件。

## 测试

```sh
go test ./...
```

覆盖：可解码基线与多扫描渐进 JPEG 在不同位置插入 EXIF 后的精确字节还原、解码像素一致性与幂等性；结构夹具验证仅删除指定 EXIF 段。
