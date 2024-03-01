import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_06675181E7B5E1030B3D40926E2A47D3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2452580b-bbe8-5d54-888e-6f8fffb055cf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8401-L8414"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "14d963fd03187afb7afabc208e36d8bb45ec818b27782a6c3037229f82bf22d6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b617253b3695fd498d645bd8278d1bdae2bc36bd4da713c6938e3fe6b0cdb9a4"
		reason = "NetWire"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ORANGE VIEW LIMITED" and pe.signatures[i].serial=="06:67:51:81:e7:b5:e1:03:0b:3d:40:92:6e:2a:47:d3")
}
