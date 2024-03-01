rule SIGNATURE_BASE_CN_Honker_Webshell_PHP_Linux : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file linux.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "8d94f1c5-2139-5d0d-8af9-9c30a0359910"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L93-L108"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "78339abb4e2bb00fe8a012a0a5b7ffce305f4e06"
		logic_hash = "2c6278acd123e0d41ed4f0f8f0da27d5de1ad56efb8102c9eae442838a0416d0"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<form name=form1 action=exploit.php method=post>" fullword ascii
		$s1 = "<title>Changing CHMOD Permissions Exploit " fullword ascii

	condition:
		uint16(0)==0x696c and filesize <6KB and all of them
}
