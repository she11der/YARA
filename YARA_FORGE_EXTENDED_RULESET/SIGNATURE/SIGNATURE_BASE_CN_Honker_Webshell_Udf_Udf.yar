rule SIGNATURE_BASE_CN_Honker_Webshell_Udf_Udf : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file udf.php"
		author = "Florian Roth (Nextron Systems)"
		id = "07252f2d-1a99-5f21-940d-899a4821b511"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L196-L211"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "df63372ccab190f2f1d852f709f6b97a8d9d22b9"
		logic_hash = "c7db32b5e66601e0b8322ac67b6b9ba8d6222891ed01db557bfac9985140421a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<?php // Source  My : Meiam  " fullword ascii
		$s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii

	condition:
		filesize <430KB and all of them
}
