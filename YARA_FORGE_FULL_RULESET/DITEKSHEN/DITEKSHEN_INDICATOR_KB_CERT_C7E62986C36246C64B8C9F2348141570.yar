import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_C7E62986C36246C64B8C9F2348141570 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "44d75e1d-5d5b-5d6f-8f7b-d94cd3908ed7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1058-L1069"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "dfb669ad42ac16d954405dc243b9d81dd9a748a14044d1fce3b71b490c58c82e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f779e06266802b395ef6d3dbfeb1cc6a0a2cfc47"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LLC Mail.Ru" and pe.signatures[i].serial=="c7:e6:29:86:c3:62:46:c6:4b:8c:9f:23:48:14:15:70")
}
