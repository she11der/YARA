rule TRELLIX_ARC_Amba_Ransomware : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect Amba Ransomware"
		author = "Marc Rivero | McAfee ATR Team"
		id = "961f2892-e462-55e4-bd96-7dff895cb1e6"
		date = "2017-07-03"
		modified = "2020-08-14"
		reference = "https://www.enigmasoftware.com/ambaransomware-removal/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_amba.yar#L1-L41"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "b9b6045a45dd22fcaf2fc13d39eba46180d489cb4eb152c87568c2404aecac2f"
		logic_hash = "0830ab49956711d3e6ad64785edcf54146a24756c4ab66384305dc18091867bd"
		score = 75
		quality = 68
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Amba"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "64DCRYPT.SYS" fullword wide
		$s2 = "32DCRYPT.SYS" fullword wide
		$s3 = "64DCINST.EXE" fullword wide
		$s4 = "32DCINST.EXE" fullword wide
		$s5 = "32DCCON.EXE" fullword wide
		$s6 = "64DCCON.EXE" fullword wide
		$s8 = "32DCAPI.DLL" fullword wide
		$s9 = "64DCAPI.DLL" fullword wide
		$s10 = "ICYgc2h1dGRvd24gL2YgL3IgL3QgMA==" fullword ascii
		$s11 = "QzpcVXNlcnNcQUJDRFxuZXRwYXNzLnR4dA==" fullword ascii
		$s12 = ")!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v)" fullword ascii
		$s13 = "RGVmcmFnbWVudFNlcnZpY2U="
		$s14 = "LWVuY3J5cHQgcHQ5IC1wIA=="
		$s15 = "LWVuY3J5cHQgcHQ3IC1wIA=="
		$s16 = "LWVuY3J5cHQgcHQ2IC1wIA=="
		$s17 = "LWVuY3J5cHQgcHQzIC1wIA=="

	condition:
		( uint16(0)==0x5a4d and filesize <3000KB and (8 of them )) or ( all of them )
}
