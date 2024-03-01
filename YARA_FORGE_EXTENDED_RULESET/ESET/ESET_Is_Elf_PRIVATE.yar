private rule ESET_Is_Elf_PRIVATE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "6389dc72-ac97-5366-83f2-2e9bcf618ae4"
		date = "2016-11-01"
		modified = "2016-11-01"
		reference = "https://github.com/eset/malware-ioc"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/moose/linux-moose.yar#L32-L39"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "2a3c9a875852cd3ce86d43b9e4a6ba786ecbae1f18bba73a3bef5b7e8ba67a3b"
		score = 75
		quality = 80
		tags = ""

	strings:
		$header = { 7F 45 4C 46 }

	condition:
		$header at 0
}
