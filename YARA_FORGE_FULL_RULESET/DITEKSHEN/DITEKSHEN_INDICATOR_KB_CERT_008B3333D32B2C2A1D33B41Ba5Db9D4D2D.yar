import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_008B3333D32B2C2A1D33B41Ba5Db9D4D2D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "90947492-2f42-5d90-b635-62a5f7e79ffc"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6742-L6757"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "c15a248dd52e7e888da381fda296cf19c53196ef52c4c4ce74af646d427eccde"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7ecaa9a507a6672144a82d453413591067fc1d27"
		hash1 = "5d5684ccef3ce3b6e92405f73794796e131d3cb1424d757828c3fb62f70f6227"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BOOK CAF\\xC3\\x89" and (pe.signatures[i].serial=="8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d" or pe.signatures[i].serial=="00:8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d"))
}
