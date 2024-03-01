import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_B64_Encoded_Useragent : FILE
{
	meta:
		description = "Detects executables containing base64 encoded User Agent"
		author = "ditekSHen"
		id = "e6a6eba2-587f-5b6b-b23d-4e4aa5289d1d"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1236-L1245"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "ee06d3d9f2f7a294ce0f117d5838fe86ae77f98da0ba30551b0b42811227b1bd"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "TW96aWxsYS81LjAgK" ascii wide
		$s2 = "TW96aWxsYS81LjAgKFdpbmRvd3M" ascii wide

	condition:
		uint16(0)==0x5a4d and any of them
}
