import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7Ab21306B11Ff280A93Fc445876988Ab : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "583fccef-3ad5-5f9a-a030-d6bf9ebed00f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4392-L4403"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "aa93d36d472d24cdd937c323ffa048fc71984fcf8a13400618ec8a0f2c172fc0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6d0d10933b355ee2d8701510f22aff4a06adbe5b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ABC BIOS d.o.o." and pe.signatures[i].serial=="7a:b2:13:06:b1:1f:f2:80:a9:3f:c4:45:87:69:88:ab")
}
