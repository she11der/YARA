import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_084B6F19898214A02A5F32E6Ea69F0Fd : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "37149424-6ce7-56db-98c5-3895bf3f5c9b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5897-L5908"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "844339ec8aaf93e279b294830a842f007d97adc4be4f6910d143ee16e5710ed5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4b89f40ba2c83c3e65d2be59abb3385cde401581"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TORG-ALYANS, LLC" and pe.signatures[i].serial=="08:4b:6f:19:89:82:14:a0:2a:5f:32:e6:ea:69:f0:fd")
}
