rule SIGNATURE_BASE_Beepservice_Hacktool : FILE
{
	meta:
		description = "Detects BeepService Hacktool used by Chinese APT groups"
		author = "Florian Roth (Nextron Systems)"
		id = "8813a01a-10db-52e7-bb1e-322864e87b15"
		date = "2016-05-12"
		modified = "2023-12-05"
		reference = "https://goo.gl/p32Ozf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_beepservice.yar#L10-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "176136e8a5ffec258caebf8d6b452b556093c5998414a7c9a4451ad78482f862"
		score = 85
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "032df812a68852b6f3822b9eac4435e531ca85bdaf3ee99c669134bd16e72820"
		hash2 = "e30933fcfc9c2a7443ee2f23a3df837ca97ea5653da78f782e2884e5a7b734f7"
		hash3 = "ebb9c4f7058e19b006450b8162910598be90428998df149977669e61a0b7b9ed"
		hash4 = "6db2ffe7ec365058f9d3b48dcca509507c138f19ade1adb5f13cf43ea0623813"

	strings:
		$x1 = "\\\\%s\\admin$\\system32\\%s" fullword ascii
		$s1 = "123.exe" fullword ascii
		$s2 = "regclean.exe" fullword ascii
		$s3 = "192.168.88.69" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and $x1 and 1 of ($s*)
}
