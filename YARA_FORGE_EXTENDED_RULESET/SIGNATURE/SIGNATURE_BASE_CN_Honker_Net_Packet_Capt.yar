rule SIGNATURE_BASE_CN_Honker_Net_Packet_Capt : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file net_packet_capt.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "16e19be7-3805-5e2b-baa6-20554fb7a5cf"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1860-L1878"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "2d45a2bd9e74cf14c1d93fff90c2b0665f109c52"
		logic_hash = "b158199a27f1260da5f5c1a8e99bb1cc3d19fe2a10577cc5932f097ff39d4ef8"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "(*.sfd)" fullword ascii
		$s2 = "GetLaBA" fullword ascii
		$s3 = "GAIsProcessorFeature" fullword ascii
		$s4 = "- Gablto " ascii
		$s5 = "PaneWyedit" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <50KB and all of them
}
