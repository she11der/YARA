import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_Deletewindefenderquarantinefiles : FILE
{
	meta:
		description = "Detects executables embedding anti-forensic artifacts of deleting Windows defender quarantine files"
		author = "ditekSHen"
		id = "a2b5c531-4e51-5c44-838b-3dffc2ed0263"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2321-L2335"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1cf82a8fb6c878cb3aaeaf36eb346b2f8038e166e8ce7b5c214769e475ae91de"
		score = 40
		quality = 29
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "rmdir C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\Entries /S" ascii wide nocase
		$s2 = "rmdir C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\Resources /S" ascii wide nocase
		$s3 = "rmdir C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\ResourceData /S" ascii wide nocase
		$r1 = "rmdir" ascii wide nocase
		$p1 = "Microsoft\\Windows Defender\\Quarantine\\Entries /S" ascii wide nocase
		$p2 = "Microsoft\\Windows Defender\\Quarantine\\Resources /S" ascii wide nocase
		$p3 = "Microsoft\\Windows Defender\\Quarantine\\ResourceData /S" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and (2 of ($s*) or (1 of ($r*) and 2 of ($p*)))
}
