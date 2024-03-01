rule SIGNATURE_BASE_Wildneutron_Sample_1 : FILE
{
	meta:
		description = "Wild Neutron APT Sample Rule"
		author = "Florian Roth (Nextron Systems)"
		id = "7bcb407f-7f01-540a-852c-a37456270888"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_wildneutron.yar#L10-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2b5065a3d0e0b8252a987ef5f29d9e1935c5863f5718b83440e68dc53c21fa94"
		logic_hash = "d8044761fa51f2afd16eb096aa9e896483387c47e10ce922f2ef32ebcbd1a520"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "LiveUpdater.exe" fullword wide
		$s1 = "id-at-postalAddress" fullword ascii
		$s2 = "%d -> %d (default)" fullword wide
		$s3 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide
		$s8 = "id-ce-keyUsage" fullword ascii
		$s9 = "Key Usage" fullword ascii
		$s32 = "UPDATE_ID" fullword wide
		$s37 = "id-at-commonName" fullword ascii
		$s38 = "2008R2" fullword wide
		$s39 = "RSA-alt" fullword ascii
		$s40 = "%02d.%04d.%s" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <800KB and all of them
}
