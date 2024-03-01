rule SIGNATURE_BASE_Stuxnet_S7Hkimdb : FILE
{
	meta:
		description = "Stuxnet Sample - file s7hkimdb.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "e4cb277f-5eee-5405-9d48-d06657392323"
		date = "2016-07-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_stuxnet.yar#L152-L188"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "a44063b6a542eca17f46802e9f644540f1d6b6cb9777c20ef9ea14e44c341a1c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4071ec265a44d1f0d42ff92b2fa0b30aafa7f6bb2160ed1d0d5372d70ac654bd"

	strings:
		$x1 = "S7HKIMDX.DLL" fullword wide
		$op1 = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
		$op2 = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
		$op3 = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and $x1 and all of ($op*))
}
