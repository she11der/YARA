rule SIGNATURE_BASE_Explosion_Sample_2 : FILE
{
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		author = "Florian Roth (Nextron Systems)"
		id = "8be7ed50-0bfc-5302-b4fa-8817bf1750d7"
		date = "2015-04-03"
		modified = "2023-12-05"
		reference = "http://goo.gl/5vYaNb"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_volatile_cedar.yar#L40-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "62fe6e9e395f70dd632c70d5d154a16ff38dcd29"
		logic_hash = "db7ead96e0a9b4cf5c5cc885eac421cc11988f60d03f94de5fe828899d115bf0"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "serverhelp.dll" fullword wide
		$s1 = "Windows Help DLL" fullword wide
		$s5 = "SetWinHoK" fullword ascii

	condition:
		all of them and uint16(0)==0x5A4D
}
