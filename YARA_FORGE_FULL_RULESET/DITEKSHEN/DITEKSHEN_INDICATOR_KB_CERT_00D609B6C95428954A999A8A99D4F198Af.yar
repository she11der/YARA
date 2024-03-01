import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D609B6C95428954A999A8A99D4F198Af : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e1b732d2-24fd-5819-a26a-049a9a569089"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5099-L5110"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "62eecc7cf240b9de6e04a43413bbeb84b673e9d3f1c4d67ec4082c099c6a87db"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b1d8033dd7ad9e82674299faed410817e42c4c40"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Fudl" and pe.signatures[i].serial=="00:d6:09:b6:c9:54:28:95:4a:99:9a:8a:99:d4:f1:98:af")
}
