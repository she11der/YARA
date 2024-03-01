import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Df7139E106Dbb68Dfe4De97D862Af708 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8da7c163-02a7-571e-a995-c1d500d90b5b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5776-L5787"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "503ff5f570191ac61a20c2a6ffa5117d5c3ed632c04c4a02c710644c18a494d0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4ac627227a25f0914f3a73ff85d90b45da589329"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "zPfPJHDCzusZRYQYJZGZoFfZmvYtSlFXDPQKtoQzc" and pe.signatures[i].serial=="00:df:71:39:e1:06:db:b6:8d:fe:4d:e9:7d:86:2a:f7:08")
}
