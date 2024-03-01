import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_References_VPN : FILE
{
	meta:
		description = "Detects executables referencing many VPN software clients. Observed in infosteslers"
		author = "ditekSHen"
		id = "301977a8-0619-50a2-a718-78ff9e039e65"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1898-L1912"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5bef727d3c6fa7ea01c16e7b1fdf146b4cef58c06189bf8540bbfe7915790578"
		score = 40
		quality = 31
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "\\VPN\\NordVPN" ascii wide nocase
		$s2 = "\\VPN\\OpenVPN" ascii wide nocase
		$s3 = "\\VPN\\ProtonVPN" ascii wide nocase
		$s4 = "\\VPN\\DUC\\" ascii wide nocase
		$s5 = "\\VPN\\PrivateVPN" ascii wide nocase
		$s6 = "\\VPN\\PrivateVPN" ascii wide nocase
		$s7 = "\\VPN\\EarthVPN" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 3 of them
}
