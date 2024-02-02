rule SIGNATURE_BASE_PHANTASMA_Php
{
	meta:
		description = "Semi-Auto-generated  - file PHANTASMA.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "21ff4cee-9cdc-57d1-9c43-e033fdb47de0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4914-L4927"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "52779a27fa377ae404761a7ce76a5da7"
		logic_hash = "d4a2a1bcc1ff3264b35f2b05d7de664b56807977f2a793fd87206f046a185d3b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = ">[*] Safemode Mode Run</DIV>"
		$s1 = "$file1 - $file2 - <a href=$SCRIPT_NAME?$QUERY_STRING&see=$file>$file</a><br>"
		$s2 = "[*] Spawning Shell"
		$s3 = "Cha0s"

	condition:
		2 of them
}