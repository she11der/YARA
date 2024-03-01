import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Go_Golazagne : FILE
{
	meta:
		description = "Detects Go executables using GoLazagne"
		author = "ditekSHen"
		id = "3b54892d-8015-518c-af0b-03ddd65478f6"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1543-L1552"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9618f8a6eb9a5db01b7a58a469309220b1e22afe928006d642e5404380f312f1"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "/goLazagne/" ascii nocase
		$s2 = "Go build ID:" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
