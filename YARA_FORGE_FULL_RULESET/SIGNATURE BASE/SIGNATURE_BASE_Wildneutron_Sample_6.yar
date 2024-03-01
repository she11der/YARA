rule SIGNATURE_BASE_Wildneutron_Sample_6 : FILE
{
	meta:
		description = "Wild Neutron APT Sample Rule"
		author = "Florian Roth (Nextron Systems)"
		id = "c5d87cad-d1ca-5766-90c1-fc8ecfa3f14f"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_wildneutron.yar#L135-L149"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4bd548fe07b19178281edb1ee81c9711525dab03dc0b6676963019c44cc75865"
		logic_hash = "7dc7f9815f2b2c934ecf93f5813bdb87364b2b9e2a5aebc04f76cfff43e46d30"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "mshtaex.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <310KB and all of them
}
