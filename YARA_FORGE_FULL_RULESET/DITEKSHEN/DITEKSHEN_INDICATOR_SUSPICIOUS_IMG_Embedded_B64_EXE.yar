import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_IMG_Embedded_B64_EXE : FILE
{
	meta:
		description = "Detects images with specific base64 markers and/or embedding (reversed) base64-encoded executables"
		author = "ditekSHen"
		id = "c620b461-5ad8-530b-a3e1-f75a9e30534e"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2394-L2411"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0fe1328aba3b30820e3885c87a93e52306bd25abc5912378a12e1213a686cd39"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$m1 = "<<BASE64_START>>" ascii
		$m2 = "<<BASE64_END>>" ascii
		$m3 = "BASE64_START" ascii
		$m4 = "BASE64_END" ascii
		$m5 = "BASE64-START" ascii
		$m6 = "BASE64-END" ascii
		$m7 = "BASE64START" ascii
		$m8 = "BASE64END" ascii
		$h1 = "TVqQA" ascii
		$h2 = "AQqVT" ascii

	condition:
		( uint32(0)==0xd8ff or uint32(0)==0x474e5089 or uint16(0)==0x4d42) and ((2 of ($m*)) or (1 of ($h*)))
}
