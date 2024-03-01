import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_661Ba8F3C9D1B348413484E9A49502F7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "75fb83a1-c493-510a-8c01-4cc699d71465"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1871-L1882"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "661af02d7a206f50e996caf690ded541acab8c8268df9e86744d36f7322efe5c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4ca944c9b69f72be3e95f385bdbc70fc7cff4c3ebb76a365bf0ab0126b277b2d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Unique Digital Services Ltd." and pe.signatures[i].serial=="66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7")
}
