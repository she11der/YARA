rule SIGNATURE_BASE_Wildneutron_Sample_3 : FILE
{
	meta:
		description = "Wild Neutron APT Sample Rule"
		author = "Florian Roth (Nextron Systems)"
		id = "1c5d1442-b2be-5a34-b5c9-78aaf67072c4"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_wildneutron.yar#L59-L83"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c2c761cde3175f6e40ed934f2e82c76602c81e2128187bab61793ddb3bc686d0"
		logic_hash = "16d511412576df2eb6d9646856d37bd94af7648cc602510696b74fa0534e405d"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "178.162.197.9" fullword ascii
		$x2 = "\"http://fw.ddosprotected.eu:80 /opts resolv=drfx.chickenkiller.com\"" fullword wide
		$s1 = "LiveUpdater.exe" fullword wide
		$s2 = "id-at-postalAddress" fullword ascii
		$s3 = "%d -> %d (default)" fullword wide
		$s4 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide
		$s5 = "id-at-serialNumber" fullword ascii
		$s6 = "ECDSA with SHA256" fullword ascii
		$s7 = "Acer LiveUpdater" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <2020KB and (1 of ($x*) or all of ($s*))
}
