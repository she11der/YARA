import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_205483936F360924E8D2A4Eb6D3A9F31 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5cce232b-4dfc-5931-a4ea-2e3df5616026"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7615-L7627"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "09bf63b88eda95aae094cecb868838f08b88a6b4fe2993145e20293034c12863"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "430dbeff2f6df708b03354d5d07e78400cfed8e9"
		hash1 = "e58b9bbb7bcdf3e901453b7b9c9e514fed1e53565e3280353dccc77cde26a98e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SATURN CONSULTANCY LTD" and pe.signatures[i].serial=="20:54:83:93:6f:36:09:24:e8:d2:a4:eb:6d:3a:9f:31")
}
