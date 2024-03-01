rule SIGNATURE_BASE_FVEY_Shadowbroker_User_Tool
{
	meta:
		description = "Auto-generated rule - file user.tool.elatedmonkey"
		author = "Florian Roth (Nextron Systems)"
		id = "b1ca04e5-bac7-5247-b2d4-82c3515c92fc"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fvey_shadowbroker_dec16.yar#L180-L193"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8135c07b8c217e81f7618d58c9c3da6585cdb9b8f7afab85bb6556c5b846ba64"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "98ae935dd9515529a34478cb82644828d94a2d273816d50485665535454e37cd"

	strings:
		$x5 = "ELATEDMONKEY will only work of apache executes scripts" fullword ascii

	condition:
		1 of them
}
