import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_091736D368A5980Ebeb433A0Ecb49Fbb : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "fb9446b5-2d49-51de-bedb-ea541d415ae2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2131-L2142"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "858a98ba8fd3244b2c0f6d3dd89a294b0187dd1a82cdcca67c162985d80ca6ed"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b1c1dc94f0c775deeb46a0a019597c4ac27ab2810e3b3241bdc284d2fccf3eb5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ELEKSIR, OOO" and pe.signatures[i].serial=="09:17:36:d3:68:a5:98:0e:be:b4:33:a0:ec:b4:9f:bb")
}
