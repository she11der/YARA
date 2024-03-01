import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6D450Cc59Acdb4B7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "845e3f48-5660-525e-bd18-5953c64322f1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6974-L6985"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8328159dce3586c26b777f92d7a87e0660520cf08d122505d34ed427bdd7ff6f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "bd3ac678cabb6465854880dd06b7b6cd231def89"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CancellationTokenSource" and pe.signatures[i].serial=="6d:45:0c:c5:9a:cd:b4:b7")
}
