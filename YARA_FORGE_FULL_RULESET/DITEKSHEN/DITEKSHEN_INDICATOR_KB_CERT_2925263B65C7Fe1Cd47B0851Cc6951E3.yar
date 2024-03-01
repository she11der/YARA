import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2925263B65C7Fe1Cd47B0851Cc6951E3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "9e531592-b68c-550b-8609-51f7c9ac63ae"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L811-L822"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "163293ce805cdd3ec265fb9c527a5ce19ddab0f6b96355acb636c941ce0bc5f2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "88ef10f0e160b1b4bb8f0777a012f6b30ac88ac8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "tuning buddy limited" and pe.signatures[i].serial=="29:25:26:3b:65:c7:fe:1c:d4:7b:08:51:cc:69:51:e3")
}
