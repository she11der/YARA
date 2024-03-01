rule SIGNATURE_BASE_CN_Honker__Wwwscan_Wwwscan_Wwwscan_Gui : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files wwwscan.exe, wwwscan.exe, wwwscan_gui.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "02f80151-4dfb-5b14-9145-312a9bd2c609"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L2380-L2398"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0fd6ab38dca839605c1b7cd51a4a8d3268551f0725ccee7c7521f13d6f9e7076"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "6dbffa916d0f0be2d34c8415592b9aba690634c7"
		hash1 = "6bed45629c5e54986f2d27cbfc53464108911026"
		hash2 = "897b66a34c58621190cb88e9b2a2a90bf9b71a53"

	strings:
		$s1 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii
		$s2 = "<Usage>:  %s <HostName|Ip> [Options]" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
