import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Embedded_Gzip_B64Encoded_File : FILE
{
	meta:
		description = "Detects executables containing bas64 encoded gzip files"
		author = "ditekSHen"
		id = "e50f8560-d53b-5388-b94d-d104b7c064f2"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L978-L987"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "431e5a45bf8ed5874b330419675b3d43eb6a563c42873730e823cdd7d6efba97"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "H4sIAAAAAAA" ascii wide
		$s2 = "AAAAAAAIs4H" ascii wide

	condition:
		uint16(0)==0x5a4d and 1 of them
}
