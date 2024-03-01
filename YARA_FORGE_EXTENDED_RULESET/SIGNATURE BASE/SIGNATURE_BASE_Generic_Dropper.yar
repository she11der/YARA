rule SIGNATURE_BASE_Generic_Dropper : FILE
{
	meta:
		description = "Detects Dropper PDB string in file"
		author = "Florian Roth (Nextron Systems)"
		id = "60ce6a5c-2e12-515b-b8cb-8c87500cb37b"
		date = "2018-03-03"
		modified = "2023-12-05"
		reference = "https://goo.gl/JAHZVL"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_dropper_pdb.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e4ef83796d232edf34a6339e00db486612a88ff2d054f1afcd524def2e53b3b7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\Release\\Dropper.pdb"
		$s2 = "\\Release\\dropper.pdb"
		$s3 = "\\Debug\\Dropper.pdb"
		$s4 = "\\Debug\\dropper.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <900KB and 1 of them
}
