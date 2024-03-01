import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1E72A72351Aecf884Df9Cdb77A16Fd84 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7972befe-3a88-5ea5-a865-3d008b712bc9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2157-L2168"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6555b89f1643f2e461a936df402dcbe8dd5100a1def76c7c6d8f792d1c0ed006"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f945bbea1c2e2dd4ed17f5a98ea7c0f0add6bfc3d07353727b40ce48a7d5e48f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Buket and Co." and pe.signatures[i].serial=="1e:72:a7:23:51:ae:cf:88:4d:f9:cd:b7:7a:16:fd:84")
}
