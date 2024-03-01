import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D7C432E8D4Edef515Bfb9D1C214Ff0F5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "fc3fd388-91f6-5f53-a284-4ef0a7d22290"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2261-L2272"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9ef64774a0b6b11820321cd36d49213ad245cea82960aab99bb18e44a2ee79a8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6256d3ca79330f7bd912a88e59f9a4f3bdebdcd6b9c55cda4e733e26583b3d61"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LLC \"MILKY PUT\"" and pe.signatures[i].serial=="00:d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5")
}
