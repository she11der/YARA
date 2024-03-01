import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_778906D40695F65Ba518Db760Df44Cd3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "87f5a591-ed92-5ee8-99f8-04afe302609e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3698-L3709"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2687ec82b9c968dca91b8f54c600fae794d01be43a31cce4b0e6ef63672870fd"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1103debcb1e48f7dda9cec4211c0a7a9c1764252"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="77:89:06:d4:06:95:f6:5b:a5:18:db:76:0d:f4:4c:d3")
}
