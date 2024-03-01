import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_04C7Cdcc1698E25B493Eb4338D5E2F8B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "446608c2-4c9e-56a9-8ac4-2c90397d68e5"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L837-L848"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "d1e81d040a279d6024989acbdd40f69de99c97baf789591400370806e846a1c4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "60974f5cc654e6f6c0a7332a9733e42f19186fbb"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "3AN LIMITED" and pe.signatures[i].serial=="04:c7:cd:cc:16:98:e2:5b:49:3e:b4:33:8d:5e:2f:8b")
}
