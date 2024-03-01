rule SIGNATURE_BASE_CN_Honker_Webscan_Webscan : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WebScan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "1545494b-9a74-5b2e-921c-e54dd5ac4b51"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1790-L1805"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a0b0e2422e0e9edb1aed6abb5d2e3d156b7c8204"
		logic_hash = "a714fe90dce33180b8074e2c3a16fc1829ed2a7b387eb92aec8a147cff9e57a4"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "wwwscan.exe" fullword wide
		$s2 = "WWWScan Gui" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <700KB and all of them
}
