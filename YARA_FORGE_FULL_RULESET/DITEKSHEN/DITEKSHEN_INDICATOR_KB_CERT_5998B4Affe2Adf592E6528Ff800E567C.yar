import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5998B4Affe2Adf592E6528Ff800E567C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "b81787fd-a8f1-5640-bf8a-8129f708a337"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L876-L887"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "d9f589ce6367517f3c93b7b0675b19249108849e52bd9264e31bf8109e5a121f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d990d584c856bd28eab641c3c3a0f80c0b71c4d7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BEAT GOES ON LIMITED" and pe.signatures[i].serial=="59:98:b4:af:fe:2a:df:59:2e:65:28:ff:80:0e:56:7c")
}
