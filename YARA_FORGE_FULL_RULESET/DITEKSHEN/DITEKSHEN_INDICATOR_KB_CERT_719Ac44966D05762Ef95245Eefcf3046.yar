import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_719Ac44966D05762Ef95245Eefcf3046 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e215971c-67f0-5fdb-9525-7aef2559674f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5526-L5537"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2b7c5ccc7a09d3917cf8625bc3e78526ba9620eb8bb08490124c24a5c2eda629"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "57ecdfa48ed03a5a8177887090b3d1ffaf124846"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "jZQtQDMvyDRzWsoVFeitFmeNcWMtKauvidXSUrSEwqmi" and pe.signatures[i].serial=="71:9a:c4:49:66:d0:57:62:ef:95:24:5e:ef:cf:30:46")
}
