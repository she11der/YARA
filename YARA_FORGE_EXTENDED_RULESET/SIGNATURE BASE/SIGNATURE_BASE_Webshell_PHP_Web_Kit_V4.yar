rule SIGNATURE_BASE_Webshell_PHP_Web_Kit_V4 : FILE
{
	meta:
		description = "Detects PAS Tool PHP Web Kit"
		author = "Florian Roth (Nextron Systems)"
		id = "a5f915cd-b9c5-5cd3-b0a2-c15f6124737a"
		date = "2016-01-01"
		modified = "2023-12-05"
		reference = "https://github.com/wordfence/grizzly"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt29_grizzly_steppe.yar#L97-L116"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e2eaa0abd14f4dd08815c44797df707a08df1ea4e04ae69ba67d128a0fe4eff5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$php = "<?php $"
		$s1 = "(StR_ReplAcE(\"\\n\",'',"
		$s2 = ";if(PHP_VERSION<'5'){" ascii
		$s3 = "=SuBstr_rePlACe(" ascii

	condition:
		uint32(0)==0x68703f3c and $php at 0 and filesize >8KB and filesize <100KB and 2 of ($s*)
}
