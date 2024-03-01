rule SIGNATURE_BASE_Oseditor : FILE
{
	meta:
		description = "Chinese Hacktool Set - file OSEditor.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b308852c-3436-5748-9ba6-82d4c3c5fc14"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1607-L1624"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "6773c3c6575cf9cfedbb772f3476bb999d09403d"
		logic_hash = "6531c0b3c0f6123d9eda34ed028f05054e4805e5c329da4b29e4f37f9b5fc1b2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "OSEditor.exe" fullword wide
		$s2 = "netsafe" wide
		$s3 = "OSC Editor" fullword wide
		$s4 = "GIF89" ascii
		$s5 = "Unlock" ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
