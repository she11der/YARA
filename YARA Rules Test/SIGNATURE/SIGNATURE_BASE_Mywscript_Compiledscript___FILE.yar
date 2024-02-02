rule SIGNATURE_BASE_Mywscript_Compiledscript___FILE
{
	meta:
		description = "Detects a scripte with default name Mywscript compiled with Script2Exe (can also be a McAfee tool https://community.mcafee.com/docs/DOC-4124)"
		author = "Florian Roth (Nextron Systems)"
		id = "a0480a8a-5a7e-5829-851b-7301cfc9da60"
		date = "2017-07-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_mywscript_dropper.yar#L10-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "5619de9589e3d34026bf4ec223f2c6b94fcb7362c8f3c26f7582030cfc4385cf"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "515f5188ba6d039b8c38f60d3d868fa9c9726e144f593066490c7c97bf5090c8"

	strings:
		$x1 = "C:\\Projets\\vbsedit_source\\script2exe\\Release\\mywscript.pdb" fullword ascii
		$s1 = "mywscript2" fullword wide
		$s2 = "MYWSCRIPT2" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <800KB and ($x1 or 2 of them )
}