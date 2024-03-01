import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00C8Edcfe8Be174C2F204D858C5B91Dea5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "196da268-b9a3-562c-ad68-67d17ea94ccf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3828-L3839"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "56801a71547218413ab48381c412a8e1b7fd41a9f7a7c85dc6debdc38a19d6c4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7f5f205094940793d1028960e0f0e8b654f9956e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Paarcopy Oy" and pe.signatures[i].serial=="00:c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5")
}
