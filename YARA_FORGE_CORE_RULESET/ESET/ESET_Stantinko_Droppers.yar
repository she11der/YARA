import "pe"

rule ESET_Stantinko_Droppers : FILE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "fe2e6987-929a-59e3-a9ec-01a9f55fe589"
		date = "2017-07-17"
		modified = "2017-07-20"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/stantinko/stantinko.yar#L150-L170"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "c56fc85834a3e1bb1c14da37fb509c7de3009bf81d52800fe0093dc489f6deaa"
		score = 75
		quality = 80
		tags = "FILE"
		Author = "Marc-Etienne M.Léveillé"
		Description = "Stantinko droppers"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = {55 8B EC 83 EC 08 53 56 BE 80 F4 45 00 57 81 EE 80 0E 41 00 56 E8 6D 23 00 00 56 8B D8 68 80 0E 41 00 53 89 5D F8 E8 65 73 00 00 8B 0D FC F5 45}
		$s2 = {7E 5E 7F 8C 08 46 00 00 AB 57 1A BB 91 5C 00 00 FA CC FD 76 90 3A 00 00}

	condition:
		uint16(0)==0x5A4D and 1 of them
}
