import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Wirelessnetreccon : FILE
{
	meta:
		description = "Detects executables with interest in wireless interface using netsh"
		author = "ditekSHen"
		id = "15515523-fe53-5512-95f3-79d0695e7da0"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2099-L2109"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a8614a8c11e3797e7d7fb7ec2c0705fafc98ce50714e48798594e6fb5bfc1789"
		score = 40
		quality = 39
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "netsh wlan show profile" ascii wide nocase
		$s2 = "netsh wlan show profile name=" ascii wide nocase
		$s3 = "netsh wlan show networks mode=bssid" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and all of them
}
