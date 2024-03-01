import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6C8D0Cf4D1593Ee8Dc8D34Be71E90251 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "fe5cbea2-1704-550c-bd2e-82defba20f24"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3321-L3332"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "981e4b426e926bd042f25a50de40d3e3462ed5fec0cf7261523b314b908a1276"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d481d73bcf1e45db382d0e345f3badde6735d17d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dbdbecdbdfafdc" and pe.signatures[i].serial=="6c:8d:0c:f4:d1:59:3e:e8:dc:8d:34:be:71:e9:02:51")
}
