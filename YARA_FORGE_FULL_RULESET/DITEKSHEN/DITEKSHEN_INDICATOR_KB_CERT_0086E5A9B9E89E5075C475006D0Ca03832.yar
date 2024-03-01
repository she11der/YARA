import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0086E5A9B9E89E5075C475006D0Ca03832 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "898bfe5f-5ac6-51f3-be55-09279a286835"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L237-L248"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "613f21989dc369ef6b1d8e42a0d707810ef064c608e4e34ba5eb475164f14abc"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "76f6c507e0bcf7c6b881f117936f5b864a3bd3f8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BlueMarble GmbH" and pe.signatures[i].serial=="00:86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32")
}
