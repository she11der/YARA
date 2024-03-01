import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_039668034826Df47E6207Ec9Daed57C3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "8ae5f710-db8e-5d29-b247-a103f0878aa5"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L250-L261"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b9579ba5dac45e38ef7b2b3381d1651395a4f648c68ae8e6fc36a0ea2d9b6300"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f98bdfa941ebfa2fe773524e0f9bbe9072873c2f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CHOO FSP, LLC" and pe.signatures[i].serial=="03:96:68:03:48:26:df:47:e6:20:7e:c9:da:ed:57:c3")
}
