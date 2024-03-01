rule SIGNATURE_BASE_CN_Honker_Wwwscan_Gui : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wwwscan_gui.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "fffed806-4394-505a-96bd-50bf6f24aefc"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1468-L1483"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "897b66a34c58621190cb88e9b2a2a90bf9b71a53"
		logic_hash = "9c25cf33fc2f675c8db7b24f2abe03d54c0ae17927e0ca9ccd3e5b97ffc56f73"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii
		$s2 = "/eye2007Admin_login.aspx" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <280KB and all of them
}
