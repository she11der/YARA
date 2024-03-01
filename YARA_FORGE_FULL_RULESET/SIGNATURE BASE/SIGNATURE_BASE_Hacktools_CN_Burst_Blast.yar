import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Burst_Blast
{
	meta:
		description = "Disclosed hacktool set - file Blast.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "9ac723c4-e88d-5fb3-b18f-c8b764c8acf3"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1440-L1454"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b07702a381fa2eaee40b96ae2443918209674051"
		logic_hash = "77902c7b23bab80d035f1dbe074554f16f99b2c9e31c80171296a1d33f705dac"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http:" ascii
		$s1 = "@echo off" fullword ascii

	condition:
		all of them
}
