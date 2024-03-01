rule SIGNATURE_BASE_Wildneutron_Sample_9 : FILE
{
	meta:
		description = "Wild Neutron APT Sample Rule"
		author = "Florian Roth (Nextron Systems)"
		id = "dbfdbe8c-4a4a-5512-a03d-e9f80c853d48"
		date = "2015-07-10"
		modified = "2023-01-06"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_wildneutron.yar#L203-L223"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "781eb1e17349009fbae46aea5c59d8e5b68ae0b42335cb035742f6b0f4e4087e"
		logic_hash = "2029c94088e075cbcbae8d7d514cfc56add022d8776e59f04824d9ce9fd12794"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "http://get.adobe.com/flashplayer/" wide
		$s4 = " Player Installer/Uninstaller" fullword wide
		$s5 = "Adobe Flash Plugin Updater" fullword wide
		$s6 = "uSOFTWARE\\Adobe" fullword wide
		$s11 = "2008R2" fullword wide
		$s12 = "%02d.%04d.%s" fullword wide
		$s13 = "%d -> %d" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1477KB and all of them
}
