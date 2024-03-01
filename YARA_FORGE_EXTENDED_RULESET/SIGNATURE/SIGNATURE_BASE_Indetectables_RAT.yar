rule SIGNATURE_BASE_Indetectables_RAT : FILE
{
	meta:
		description = "Detects Indetectables RAT based on strings found in research by Paul Rascagneres & Ronan Mouchoux"
		author = "Florian Roth (Nextron Systems)"
		id = "f8322822-617c-50cf-8b64-60da3a202ca5"
		date = "2015-10-01"
		modified = "2023-12-05"
		reference = "http://www.sekoia.fr/blog/when-a-brazilian-string-smells-bad/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_indetectables_rat.yar#L8-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "840a0c92ac731d9e88d0bdccb39598e4ff476e8630ec08f6c4024a31e258ebd0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "081905074c19d5e32fd41a24b4c512d8fd9d2c3a8b7382009e3ab920728c7105"
		hash2 = "66306c2a55a3c17b350afaba76db7e91bfc835c0e90a42aa4cf59e4179b80229"
		hash3 = "1fa810018f6dd169e46a62a4f77ae076f93a853bfc33c7cf96266772535f6801"

	strings:
		$s1 = "Coded By M3" fullword wide
		$s2 = "Stub Undetector M3" fullword wide
		$s3 = "www.webmenegatti.com.br" wide
		$s4 = "M3n3gatt1" fullword wide
		$s5 = "TheMisterFUD" fullword wide
		$s6 = "KillZoneKillZoneKill" fullword ascii
		$s7 = "[[__M3_F_U_D_M3__]]$" fullword ascii
		$s8 = "M3_F_U_D_M3" ascii
		$s9 = "M3n3gatt1hack3r" fullword wide
		$s10 = "M3n3gatt1hack3r" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and 1 of them
}
