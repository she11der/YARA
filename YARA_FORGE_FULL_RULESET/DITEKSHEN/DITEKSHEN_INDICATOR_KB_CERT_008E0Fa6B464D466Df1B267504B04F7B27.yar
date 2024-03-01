import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_008E0Fa6B464D466Df1B267504B04F7B27 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "6de3aab7-7175-537b-8a33-56cb0662b7a6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6103-L6114"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1f992d81b63108840d457f3f1906524cf4a9d4bec4a91f7bc826fae9989d40e0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "91707c95044c5badcd51d198bdbe3a7ff3156c35"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ApcWCjFsGXwbWUJrKZ" and pe.signatures[i].serial=="00:8e:0f:a6:b4:64:d4:66:df:1b:26:75:04:b0:4f:7b:27")
}
