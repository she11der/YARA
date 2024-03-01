rule SIGNATURE_BASE_Ms11080_Withcmd : FILE
{
	meta:
		description = "Chinese Hacktool Set - file ms11080_withcmd.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "fa5002ac-d6e6-543f-8020-43dfae689b3b"
		date = "2015-06-13"
		modified = "2022-12-21"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2069-L2087"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "745e5058acff27b09cfd6169caf6e45097881a49"
		logic_hash = "cd7167269538a5dd197260682ad777f87e43cc2155acf3ce731d1a065395cf4a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
		$s2 = "\\ms11080\\ms11080\\Debug\\ms11080.pdb" ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[>] create porcess error" fullword ascii
		$s5 = "[>] ms11-080 Exploit" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 1 of them
}
