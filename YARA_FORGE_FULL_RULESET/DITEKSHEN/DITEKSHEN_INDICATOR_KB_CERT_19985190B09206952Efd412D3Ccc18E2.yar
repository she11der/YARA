import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_19985190B09206952Efd412D3Ccc18E2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "bd94cfd0-adaa-5e37-880e-8ef50328499d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5257-L5268"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6db1aaabd9a257e863a5ff771a736b705391602f7f5e2b799f8c47d3ae566f0f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "49ec0580239c07da4ffba56dc8617a8c94119c69"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "cwcpbvBhYEPeJYcCNDldHTnGK" and pe.signatures[i].serial=="19:98:51:90:b0:92:06:95:2e:fd:41:2d:3c:cc:18:e2")
}
