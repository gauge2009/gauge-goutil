/*
go build -o verifying_digital_certificate verifying_the_Validity_Period_of_a_Digital_Certificate.go
./verifying_digital_certificate
*/
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

const certPEM = `
-----BEGIN CERTIFICATE-----
MIIFpTCCA42gAwIBAgIUM1bry2SdniZQ43HiD6lTPCHdBW0wDQYJKoZIhvcNAQEL
BQAwYjELMAkGA1UEBhMCQ04xETAPBgNVBAgMCFpIRUpJQU5HMREwDwYDVQQHDAhI
QU5HWkhPVTENMAsGA1UECgwEQUlDRzEOMAwGA1UECwwFSVNUSU8xDjAMBgNVBAMM
BUdBVUdFMB4XDTI0MDcxNTAxMzU1MVoXDTI0MDgxNDAxMzU1MVowYjELMAkGA1UE
BhMCQ04xETAPBgNVBAgMCFpIRUpJQU5HMREwDwYDVQQHDAhIQU5HWkhPVTENMAsG
A1UECgwEQUlDRzEOMAwGA1UECwwFSVNUSU8xDjAMBgNVBAMMBUdBVUdFMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArDj9VL4zvYrlljPMvbATdyvxTlcP
E55N7biSFxr5ppFRz+zwbOARfu3UFD0X2d7+RuAZS3g+GBB7UVgfEP/MKHyN/Zvn
Zn+4X4ZINCZFwj5YU8326blkNu6YjZzNa0f4Q5xJIQImoB1/MQldOv+8bxAYE4gM
MIEKNRS0Sm8pKDVeNTWf9iMRdfqvAE5KJmUNP8GW7pp+M6ItO//BUga/5eRsZP6j
mNIT5zNy7grbgIAik9PP1iviai7LjuMtut+Da5KznjIP3DqfCByzZe+DXPO27q3m
/Wdyb1eZUB6qOcOu/4G77ji9W2OSUyXS+YVZfSmUiBBZoLVzAtRYDTZ5AihFmWeW
cAGKc09e8yIoW6/rc9O+VRcJ+afvMPvsaLzO/i/R2qMLBkLuGSj4AJJg/d4PjYPV
k4967d16VK6NMwyqYvvltzDuX4CRCWwA9zVNdd01E2X3/vLMQpS3Php/EUfizKus
OB2TEL6Tj2reQrhFffx3hk7XJEmsgp7ohKOO561ZKco5x6cD7nRuJkVVnhVgnFZ/
AFV0sZUG6dAqGeM7NLFE3TY6cbc5Z9gDZCPRKHn+MLYyZUnIH86CGuxJuSNFdiJb
/O0/s70ogRI4XIytvHOJLljWZVGVwri/n0uwVpvgZPypQe+Wr0TW4SVU+tKYIZkY
Zsjat00ZcaQIRKUCAwEAAaNTMFEwHQYDVR0OBBYEFIjiQzYo5u+yiX0w03EV/6Hk
FiiaMB8GA1UdIwQYMBaAFIjiQzYo5u+yiX0w03EV/6HkFiiaMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggIBAJxvcAyEkQs5+CEWUr/4lzoxzEG4AOOV
I0gyzRVEaXqvomJ+8vOOTkXoHG+cOl/gKhCc+mDTwO9/FxkXE9FHwmAaZ/jtDT+p
Vh/yqevoINAYVp38ZQxnunzA7xghtwc/amdVY9ybfeBieR9SMiyq285m/Uyqf5dV
RSvvxrhY3SIcv0r+uzgXeWYYTWu9IUPgoUQzy0YOSEgn6gZNR518e3Q1JaDwu1dT
jEJJAaM6sQn3PeN5XTwt+1tkrmz5NG2l3fRkb9Yijus85KVKWAPHsZkeVjDi/Pc4
gg1zvIJxN+/TpZEzOhBVlKsT93hND/jJLFtgDVBoIo3pVTkR7pdHq/MTn/nH+2tM
IVkqJj06mRLZoqf3GMeE+VOj8hbfaGGp1f8RK+SDuIY46Y7vTmEudRoygE2v0GT7
HkiXj/MNRzyedLHAt35BjCDZ8tib9BWUU8+nUwOgUdOOCWR90weSaNOShLBBUtfa
/Fm8gWMCvCfQYSWNP+NNlBjWW7QWd7VsGqI59y/ngkdNSIpHi2w4bcAjrIWZs4LK
B5qM0zcfku9ueO7Z3qf3i74ZVAW5hpkoOIrOQYLVeaK5si+zvXDQxST/vcKB+a82
pQbJPvsXT2k4pZKf9ttBybVaN//qMGRCKLgGF4tA1nV1ULONHJy8tly7TIi4IfTO
CrQSQrC/WQuQ
-----END CERTIFICATE-----
`

// VerifyCertificateValidity 验证数字证书的有效期
func VerifyCertificateValidity() error {
	// 解析证书
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("无法解析证书 PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("无法解析证书: %v", err)
	}

	// 获取当前时间
	currentTime := time.Now()

	// 检查当前时间是否在证书的有效期内
	if currentTime.Before(cert.NotBefore) || currentTime.After(cert.NotAfter) {
		return fmt.Errorf("证书已过期")
	}

	return nil
}

func main() {

	err := VerifyCertificateValidity()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("证书有效")
	// 你的程序逻辑
}
