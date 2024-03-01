import "pe"

rule SIGNATURE_BASE_Mimikatz_Logfile
{
	meta:
		description = "Detects a log file generated by malicious hack tool mimikatz"
		author = "Florian Roth (Nextron Systems)"
		id = "921d85fc-fb4d-57ed-b4ac-203d5c6f1e8e"
		date = "2015-03-31"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_mimikatz.yar#L103-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4591cda5bd5a555292087da26193accc4f00d7c0611be8d5ab6dd4dabb14a0ef"
		score = 80
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "SID               :" ascii fullword
		$s2 = "* NTLM     :" ascii fullword
		$s3 = "Authentication Id :" ascii fullword
		$s4 = "wdigest :" ascii fullword

	condition:
		all of them
}