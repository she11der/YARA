import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0889E4181E71B16C4A810Bee38A78419 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "e9ada9f1-4b52-5da6-ba82-3ea2625ccefd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1257-L1268"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2411f7ac79d18af295d77078c6e1c98c5a116ab24125c08946cb6ca09c28bc7b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "bce3c17815ec9f720ba9c59126ae239c9caf856d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\x8B\\x92\\xE5\\xBC\\x97\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE5\\x90\\xBE\\xE4\\xBC\\x8A\\xE5\\x90\\xBE" and pe.signatures[i].serial=="08:89:e4:18:1e:71:b1:6c:4a:81:0b:ee:38:a7:84:19")
}
