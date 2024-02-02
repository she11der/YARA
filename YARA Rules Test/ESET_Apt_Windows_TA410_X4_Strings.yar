rule ESET_Apt_Windows_TA410_X4_Strings
{
	meta:
		description = "Matches various strings found in TA410 X4"
		author = "ESET Research"
		id = "e6af4516-8b79-5182-8571-7dd530632ddc"
		date = "2020-10-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/ta410/ta410.yar#L109-L125"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "d4b2321a6d0eb0ca8d7c47596af2a45c22b3aef15d1832d64d6588a62cab312a"
		score = 75
		quality = 74
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "[X]InLoadSC" ascii wide nocase
		$s3 = "MachineKeys\\Log\\rsa.txt" ascii wide nocase
		$s4 = "MachineKeys\\Log\\output.log" ascii wide nocase

	condition:
		any of them
}