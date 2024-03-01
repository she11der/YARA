rule SIGNATURE_BASE_Sphinx_Moth_Cudacrt : FILE
{
	meta:
		description = "sphinx moth threat group file cudacrt.dll"
		author = "Kudelski Security - Nagravision SA"
		id = "233f657b-029a-5ed4-b2f7-712851297f18"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "www.kudelskisecurity.com"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sphinx_moth.yar#L9-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ae7ff3d5ffd29de80ce5dcccde9af04d2537a279fe35f6e94257d59a462ba6a0"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "HPSSOEx.dll" fullword wide
		$s1 = "255.255.255.254" fullword wide
		$s2 = "SOFTWARE\\SsoAuth\\Service" fullword wide
		$op0 = { ff 15 5f de 00 00 48 8b f8 48 85 c0 75 0d 48 8b }
		$op1 = { 45 33 c9 4c 8d 05 a7 07 00 00 33 d2 33 c9 ff 15 }
		$op2 = { e8 7a 1c 00 00 83 f8 01 74 17 b9 03 }

	condition:
		uint16(0)==0x5a4d and filesize <243KB and all of ($s*) and 1 of ($op*)
}
