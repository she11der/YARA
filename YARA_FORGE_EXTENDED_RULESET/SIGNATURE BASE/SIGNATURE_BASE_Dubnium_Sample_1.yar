rule SIGNATURE_BASE_Dubnium_Sample_1 : FILE
{
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth (Nextron Systems)"
		id = "377ecbaa-9324-562e-a973-0276d44f3feb"
		date = "2016-06-10"
		modified = "2023-12-05"
		reference = "https://goo.gl/AW9Cuu"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_dubnium.yar#L10-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "94763f42dacbeede9a72c3ecc222164a5808bd74c5d2d783c76831221a9c30c8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"

	strings:
		$key1 = "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194" fullword ascii
		$key2 = "90631f686a8c3dbc0703ffa353bc1fdf35774568ac62406f98a13ed8f47595fd" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
