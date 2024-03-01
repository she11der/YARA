import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_06De439Ba2Df4Dcd8240C211D60Cdf5E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "90623074-58ac-51fd-9b80-881d3187dc74"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7400-L7412"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a2847853e2e9cc9e6909871b3f8e6de399fb76353e997b084c92dbcfe6c1a48f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2650a1205bd7720381c00bdee5aede0ee333dc13"
		hash1 = "e3bc81a59fc45dfdfcc57b0078437061cb8c3396e1d593fcf187e3cdf0373ed1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Microleaves LTD" and pe.signatures[i].serial=="06:de:43:9b:a2:df:4d:cd:82:40:c2:11:d6:0c:df:5e")
}
