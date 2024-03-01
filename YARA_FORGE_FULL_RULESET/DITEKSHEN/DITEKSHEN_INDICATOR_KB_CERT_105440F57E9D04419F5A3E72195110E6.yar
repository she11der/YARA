import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_105440F57E9D04419F5A3E72195110E6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "44600134-156b-5762-bdae-f4c016f454a3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1400-L1411"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f8b7aebe91466a587dac366cf6483586f22f95ebc186aa139e55c6e52d276f63"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e95c7b4f2e5f64b388e968d0763da67014eb3aeb8c04bd44333ca3e151aa78c2"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CRYPTOLAYER SRL" and pe.signatures[i].serial=="10:54:40:f5:7e:9d:04:41:9f:5a:3e:72:19:51:10:e6")
}
