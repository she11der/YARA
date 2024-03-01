import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3E57584Db26A2C2Ebc24Ae3E1954Fff6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9073846e-97c7-5b2e-a81f-3bbd06699842"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1910-L1921"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "cfc68c32ceba351610651d34fb420c64bab9a3b1564d9b6392f0ee8cdcdac7de"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4ecbada12a11a5ad5fe6a72a8baaf9d67dc07556a42f6e9a9b6765e334099f4e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Zaryad LLC" and pe.signatures[i].serial=="3e:57:58:4d:b2:6a:2c:2e:bc:24:ae:3e:19:54:ff:f6")
}
