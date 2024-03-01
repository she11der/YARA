rule SIGNATURE_BASE_Httpbrowser_RAT_Sample2 : FILE
{
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "693d381f-50b0-5f06-b725-78243b67092c"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "http://snip.ly/giNB"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_threatgroup_3390.yar#L67-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c7e945131a867bf46a467784d7119c95342733cc723cdeeb76d69c8fdb326749"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c57c5a2c322af2835ae136b75283eaaeeaa6aa911340470182a9983ae47b8992"

	strings:
		$s0 = "nKERNEL32.DLL" fullword wide
		$s1 = "WUSER32.DLL" fullword wide
		$s2 = "mscoree.dll" fullword wide
		$s3 = "VPDN_LU.exeUT" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <250KB and all of them
}
