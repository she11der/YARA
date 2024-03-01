import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6B0008Bbd5Eb53F5D9E616C3Ed00000008Bbd5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "51e670b5-a679-52ef-9c07-5a2bd21f8a20"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5708-L5719"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "185334d7f484585cd88a1d89516f805d0248234a61153f8a38cc78b52d4bd764"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a24cff3a026dc6b30fb62fb01dbda704eb07164f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "microsoft.com" and pe.signatures[i].serial=="6b:00:08:bb:d5:eb:53:f5:d9:e6:16:c3:ed:00:00:00:08:bb:d5")
}
