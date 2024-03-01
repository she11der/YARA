import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00C865D49345F1Ed9A84Bea40743Cdf1D7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "2ef45336-bb59-5510-af6f-29e41c9258b9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1231-L1242"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1a43e85e8c8d254dc3ba48ee9be5c233818fd6137967cd0235e802a2de1f9564"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d5e8afa85c6bf68d31af4a04668c3391e48b24b7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\xB0\\x94\\xE5\\x93\\xA6\\xD0\\x93\\xE8\\x89\\xBE\\xE5\\xB1\\x81\\xE5\\xB1\\x81\\xE5\\x93\\xA6\\xE5\\xB1\\x81\\xE5\\x93\\xA6\\xE7\\xBB\\xB4\\xE5\\x93\\xA6\\xE8\\x89\\xBE\\xE5\\xB0\\x94\\xE8\\x89\\xBE" and pe.signatures[i].serial=="00:c8:65:d4:93:45:f1:ed:9a:84:be:a4:07:43:cd:f1:d7")
}
