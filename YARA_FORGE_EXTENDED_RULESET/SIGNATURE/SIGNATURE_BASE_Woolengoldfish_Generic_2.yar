rule SIGNATURE_BASE_Woolengoldfish_Generic_2
{
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth (Nextron Systems)"
		id = "930b928f-ff32-56b2-9e3c-dd80036ff7ef"
		date = "2015-03-25"
		modified = "2023-12-05"
		reference = "http://goo.gl/NpJpVZ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_woolengoldfish.yar#L62-L79"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "25d2ea25543b0a6330e443333f1ac7a59874631c8ee7faeb4ea6d94c62c255fc"
		score = 90
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "47b1c9caabe3ae681934a33cd6f3a1b311fd7f9f"
		hash2 = "62172eee1a4591bde2658175dd5b8652d5aead2a"
		hash3 = "7fef48e1303e40110798dfec929ad88f1ad4fbd8"
		hash4 = "c1edf6e3a271cf06030cc46cbd90074488c05564"

	strings:
		$s0 = "modules\\exploits\\littletools\\agent_wrapper\\release" ascii

	condition:
		all of them
}
