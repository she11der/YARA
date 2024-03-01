import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E3B80C0932B52A708477939B0D32186F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "41525cdd-f65a-5aad-bd99-1cdcf8b11981"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6593-L6607"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a0a95c20c5c82b460ddef686731d1053181cb5066bbb4f585a4f402f50efe030"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1d2b5d4f0de1d7ce4abf82fdc58adc43bc28adee"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BISOYETUTU LTD LIMITED" and (pe.signatures[i].serial=="e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f" or pe.signatures[i].serial=="00:e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f"))
}
