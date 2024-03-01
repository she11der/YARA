import "pe"

rule SIGNATURE_BASE_CN_Hacktool_1433_Scanner_Comp2 : FILE
{
	meta:
		description = "Detects a chinese MSSQL scanner - component 2"
		author = "Florian Roth (Nextron Systems)"
		id = "7d707be5-dad0-5d91-965b-908a8603b6c0"
		date = "2014-12-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L722-L736"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7c84d59a821531d9e741a05a23a911bb1caa825a18bb6532381e5ff38193c260"
		score = 40
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "UUUMUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUMUUU" ascii fullword

	condition:
		uint16(0)==0x5a4d and all of ($s*)
}
