import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_009Cfbb4C69008821Aaacecde97Ee149Ab : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0b0d815b-2232-5159-9b78-9227d9b2ec11"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1676-L1687"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "de04f12b1fb1e12860bf4ac077b700d180b8d412890922b75264319559fbd997"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6c7e917a2cc2b2228d6d4a0556bda6b2db9f06691749d2715af9a6a283ec987b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kivaliz Prest s.r.l." and pe.signatures[i].serial=="00:9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab")
}
