rule SIGNATURE_BASE_CN_Honker_Htran2_4 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file HTran2.4.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "21cb5ec5-900d-5092-8c2b-2d951289957c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2323-L2338"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "524f986692f55620013ab5a06bf942382e64d38a"
		logic_hash = "dd1332d3dca12513b1f8a1d10148f6fa2eb7cc809ac7cf6f4dcc9090746718b5"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Enter Your Socks Type No: [0.BindPort 1.ConnectBack 2.Listen]:" fullword ascii
		$s2 = "[+] New connection %s:%d !!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <180KB and all of them
}
