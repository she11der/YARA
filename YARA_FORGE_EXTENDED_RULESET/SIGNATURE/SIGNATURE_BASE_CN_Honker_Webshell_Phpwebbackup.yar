rule SIGNATURE_BASE_CN_Honker_Webshell_Phpwebbackup : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file phpwebbackup.php"
		author = "Florian Roth (Nextron Systems)"
		id = "eb737ea6-231c-5e8d-b976-75f1044f9f54"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L247-L262"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c788cb280b7ad0429313837082fe84e9a49efab6"
		logic_hash = "45452fc415fbafe170a1b1f5a58df40f0ec65a9a6678e675b40a8c54e2d8bd6c"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<?php // Code By isosky www.nbst.org" fullword ascii
		$s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii

	condition:
		uint16(0)==0x3f3c and filesize <67KB and all of them
}
