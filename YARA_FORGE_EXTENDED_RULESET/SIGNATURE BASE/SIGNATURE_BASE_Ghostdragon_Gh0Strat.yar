rule SIGNATURE_BASE_Ghostdragon_Gh0Strat : FILE
{
	meta:
		description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
		author = "Florian Roth (Nextron Systems)"
		id = "a74330ab-5249-5125-8f48-27aec7c6eeb4"
		date = "2016-04-23"
		modified = "2023-12-05"
		reference = "https://blog.cylance.com/the-ghost-dragon"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_ghostdragon_gh0st_rat.yar#L8-L52"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b67c7ff76c14e771c4e952a408c2c006c9ae88fda97b775747a95322aff355e7"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f9a669d22866cd041e2d520c5eb093188962bea8864fdfd0c0abb2b254e9f197"
		hash2 = "99ee5b764a5db1cb6b8a4f62605b5536487d9c35a28a23de8f9174659f65bcb2"
		hash3 = "6c7f8ba75889e0021c4616fcbee86ac06cd7f5e1e355e0cbfbbb5110c08bb6df"
		hash4 = "b803381535ac24ce7c8fdcf6155566d208dfca63fd66ec71bbc6754233e251f5"

	strings:
		$x1 = "REG ADD HKEY_LOCAL_MACHINE\\%s /v ServiceDll /t REG_EXPAND_SZ /d \"%s\"" fullword ascii
		$x2 = "Global\\REALCHEL_GLOBAL_SUBMIT_20031020_" ascii
		$x3 = "\\xclolg2.tmp" ascii
		$x4 = "Http/1.1 403 Forbidden" fullword ascii
		$x5 = "%sxsd%d.pif" fullword ascii
		$x6 = "%s\\%s32.dl_" ascii
		$x7 = "%-23s %-16s  0x%x(%02d)" fullword ascii
		$x8 = "RegSetValueEx(start)" fullword ascii
		$x9 = "%s\\%s64.dl_" ascii
		$s1 = "viewsc.dll" fullword ascii
		$s2 = "Proxy-Connection:   Keep-Alive" fullword ascii
		$s3 = "\\sfc_os.dll" ascii
		$s4 = "Mozilla/4.0 (compatible)" fullword ascii
		$s5 = "Http/1.1 403 Forbidden" fullword ascii
		$s6 = "CONNECT   %s:%d   HTTP/1.1" fullword ascii
		$s7 = "WindowsUpperVersion" fullword ascii
		$s8 = "[%d-%d-%d %d:%d:%d] (%s)" fullword ascii
		$s9 = "SOFTWARE\\Microsoft\\DataAccess\\%s" fullword ascii
		$s10 = "%s sp%d(%d)" fullword ascii
		$s11 = "OpenSC ERROR " fullword ascii
		$s12 = "get rgspath error " fullword ascii
		$s13 = "Global\\GLOBAL_SUBMIT_0234_" ascii
		$s14 = "Global\\_vc_ck_ %d" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and (1 of ($x*) or 4 of ($s*))) or (6 of them )
}
