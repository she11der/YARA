rule SIGNATURE_BASE_FVEY_Shadowbroker_User_Tool_Epichero
{
	meta:
		description = "Auto-generated rule - file user.tool.epichero.COMMON"
		author = "Florian Roth (Nextron Systems)"
		id = "b1ca04e5-bac7-5247-b2d4-82c3515c92fc"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fvey_shadowbroker_dec16.yar#L164-L178"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "36dc38f2dd630f22b87e8d9130de7d40ee3cdba45597b2b667a1a9536d990aad"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "679d194c32cbaead7281df9afd17bca536ee9d28df917b422083ae8ed5b5c484"

	strings:
		$x2 = "-irtun TARGET_IP ISH_CALLBACK_PORT"
		$x3 = "-O REVERSE_SHELL_CALLBACK_PORT -w HIDDEN_DIR" fullword ascii

	condition:
		1 of them
}
