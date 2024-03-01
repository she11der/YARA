import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_Antivm_WMIC : FILE
{
	meta:
		description = "Detects memory artifacts referencing WMIC commands for anti-VM checks"
		author = "ditekSHen"
		id = "f7166171-15b7-5e11-bbec-355764e58caa"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1977-L1987"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2c26ea8b008bf9cb4d8e24c909a3c6f5d67783b483747268f949fadc3fa72532"
		score = 40
		quality = 39
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "wmic process where \"name like '%vmwp%'\"" ascii wide nocase
		$s2 = "wmic process where \"name like '%virtualbox%'\"" ascii wide nocase
		$s3 = "wmic process where \"name like '%vbox%'\"" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 2 of them
}
