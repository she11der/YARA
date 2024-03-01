rule SIGNATURE_BASE_FVEY_Shadowbroker_User_Tool_Elgingamble
{
	meta:
		description = "Auto-generated rule - file user.tool.elgingamble.COMMON"
		author = "Florian Roth (Nextron Systems)"
		id = "344e5d5e-9fd6-5a32-ba98-945f5a35a116"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L275-L288"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "2f4dd668c59244e92ebfe0e2fc2859b2376cf1dd6fc6522e8f452787aa96365f"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4130284727ddef4610d63bfa8330cdafcb6524d3d2e7e8e0cb34fde8864c8118"

	strings:
		$x2 = "### Local exploit for" fullword ascii

	condition:
		1 of them
}
