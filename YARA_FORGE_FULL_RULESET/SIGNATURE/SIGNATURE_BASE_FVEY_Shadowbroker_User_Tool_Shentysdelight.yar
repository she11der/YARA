rule SIGNATURE_BASE_FVEY_Shadowbroker_User_Tool_Shentysdelight
{
	meta:
		description = "Auto-generated rule - file user.tool.shentysdelight.COMMON"
		author = "Florian Roth (Nextron Systems)"
		id = "b1ca04e5-bac7-5247-b2d4-82c3515c92fc"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fvey_shadowbroker_dec16.yar#L149-L162"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1acfb6aea7e208b7fd52325258219c162482deb4fa7ee87ddc4de0774e3e74f4"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a564efeaae9c13fe09a27f2d62208a1dec0a19b4a156f5cfa96a0259366b8166"

	strings:
		$s1 = "echo -ne \"/var/run/COLFILE\\0\"" fullword ascii

	condition:
		1 of them
}
