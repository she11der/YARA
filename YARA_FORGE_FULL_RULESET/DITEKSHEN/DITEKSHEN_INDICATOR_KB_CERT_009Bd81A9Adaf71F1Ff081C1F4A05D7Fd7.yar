import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_009Bd81A9Adaf71F1Ff081C1F4A05D7Fd7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "deedbc3a-8c77-5c2c-b3c1-40e5d082ec5a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2417-L2428"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "85efd10f6c49b93215c9f8f97915c62fb3ed3bb158b2137e953022b550263726"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "885b9f1306850a87598e5230fcae71282042b74e8a14cabb0a904c559b506acb"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SMART TOYS AND GAMES" and pe.signatures[i].serial=="00:9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7")
}
