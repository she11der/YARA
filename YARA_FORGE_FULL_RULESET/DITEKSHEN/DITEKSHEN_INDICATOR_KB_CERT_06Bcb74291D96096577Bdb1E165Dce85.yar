import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_06Bcb74291D96096577Bdb1E165Dce85 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e7c24edc-2e59-5ee1-ad2f-d260b4014fdd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7629-L7641"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "34f533f7c7e12aaac9a1998654fae6ffde366affa90e9cba061b356fa7190e71"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d1bde6303266977f7540221543d3f2625da24ac4"
		hash1 = "074cef597dc028b08dc2fe927ea60f09cfd5e19f928f2e4071860b9a159b365d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Revo Security SRL" and pe.signatures[i].serial=="06:bc:b7:42:91:d9:60:96:57:7b:db:1e:16:5d:ce:85")
}
