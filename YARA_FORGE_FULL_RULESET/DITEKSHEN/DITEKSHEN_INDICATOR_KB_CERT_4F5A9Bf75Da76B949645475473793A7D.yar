import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4F5A9Bf75Da76B949645475473793A7D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "094b56b9-15fc-5366-9023-c706613882c4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L993-L1004"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8f00efcd62a934fb6ec0205dc1d7bb7f7f3ab168150fee942536ef92f686d21d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f7de21bbdf5effb0f6739d505579907e9f812e6f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EXEC CONTROL LIMITED" and pe.signatures[i].serial=="4f:5a:9b:f7:5d:a7:6b:94:96:45:47:54:73:79:3a:7d")
}
