import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Attrib : FILE
{
	meta:
		description = "Detects executables using attrib with suspicious attributes attributes"
		author = "ditekSHen"
		id = "69925f45-b8a9-516c-857c-7a687b32e0c6"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1258-L1266"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2d26581037a34f32b3e3aa6df5570f0de0b9e070cbe6190318a99c6f147250d8"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "attrib +h +r +s" ascii wide

	condition:
		uint16(0)==0x5a4d and any of them
}
