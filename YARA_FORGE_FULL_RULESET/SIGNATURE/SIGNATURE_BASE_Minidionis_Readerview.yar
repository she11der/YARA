rule SIGNATURE_BASE_Minidionis_Readerview : FILE
{
	meta:
		description = "MiniDionis Malware - file readerView.exe / adobe.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "dc8d4311-2a87-5c9b-95ff-52708f293f01"
		date = "2015-07-20"
		modified = "2023-12-05"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_minidionis.yar#L10-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "45ae1be675f2b7b3d89aea2bde66f9f96b55b6fbf81e3783c209c7d6d4355026"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ee5eb9d57c3611e91a27bb1fc2d0aaa6bbfa6c69ab16e65e7123c7c49d46f145"
		hash2 = "a713982d04d2048a575912a5fc37c93091619becd5b21e96f049890435940004"
		hash3 = "88a40d5b679bccf9641009514b3d18b09e68b609ffaf414574a6eca6536e8b8f"
		hash4 = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
		hash5 = "ed7abf93963395ce9c9cba83a864acb4ed5b6e57fd9a6153f0248b8ccc4fdb46"
		hash6 = "56ac764b81eb216ebed5a5ad38e703805ba3e1ca7d63501ba60a1fb52c7ebb6e"

	strings:
		$s1 = "%ws_out%ws" fullword wide
		$s2 = "dnlibsh" fullword ascii
		$op0 = { 0f b6 80 68 0e 41 00 0b c8 c1 e1 08 0f b6 c2 8b }
		$op1 = { 8b ce e8 f8 01 00 00 85 c0 74 41 83 7d f8 00 0f }
		$op2 = { e8 2f a2 ff ff 83 20 00 83 c8 ff 5f 5e 5d c3 55 }

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of ($s*) and 1 of ($op*)
}
