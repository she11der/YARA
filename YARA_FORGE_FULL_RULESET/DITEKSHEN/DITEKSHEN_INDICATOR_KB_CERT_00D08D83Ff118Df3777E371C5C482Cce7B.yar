import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D08D83Ff118Df3777E371C5C482Cce7B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d4857ec5-2c99-51f8-a5b8-938c8d83169e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4994-L5005"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b6c7f5c57c79d11132535bedce77276f67c4f854f5e8ef2c12aced64f8a188d0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8a1bcf92ea961b8bc8817b0630f34607ccb5bff2"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMO-K Limited Liability Company" and pe.signatures[i].serial=="00:d0:8d:83:ff:11:8d:f3:77:7e:37:1c:5c:48:2c:ce:7b")
}
