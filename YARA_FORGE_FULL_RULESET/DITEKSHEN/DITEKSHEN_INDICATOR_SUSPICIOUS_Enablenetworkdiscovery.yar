import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_Enablenetworkdiscovery : FILE
{
	meta:
		description = "Detects binaries manipulating Windows firewall to enable permissive network discovery"
		author = "ditekSHen"
		id = "b1203e7a-b4f3-587e-aaea-a4cccaedc07d"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1999-L2008"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6c28a33849d1c6c72b65926a81e96f0e3f5b9bb0a48739bf4240a16f6a10dcea"
		score = 40
		quality = 41
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "netsh advfirewall firewall set rule group=\"Network Discovery\" new enable=Yes" ascii wide nocase
		$s2 = "netsh advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=Yes" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and all of them
}
