import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00F13A4F94Bf233525 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1d048571-661e-5d7f-a255-f07b84069b20"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6831-L6845"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "29284d9ced0d5e6d587edc9727321cdc7bf5ce4ad8407d460afa7f1e6d1bcb90"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "974eb056bb7467d54aae25a908ce661dac59c786"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SocketOptionName" and (pe.signatures[i].serial=="f1:3a:4f:94:bf:23:35:25" or pe.signatures[i].serial=="00:f1:3a:4f:94:bf:23:35:25"))
}
