import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00849Ea0945Dd2Ea2Dc3Cc2486578A5715 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8584af2e-6b1e-5141-abbf-84e414ffaead"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6186-L6197"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "824744510e73cd6717e3626a5a250466bfb5817fd7172fc32466c2e68e20947b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8c56adfb8fba825aa9a4ab450c71d45b950e55a4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Biglin" and pe.signatures[i].serial=="00:84:9e:a0:94:5d:d2:ea:2d:c3:cc:24:86:57:8a:57:15")
}
