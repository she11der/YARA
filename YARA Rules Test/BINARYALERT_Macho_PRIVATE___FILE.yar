rule BINARYALERT_Macho_PRIVATE___FILE
{
	meta:
		description = "Mach-O binaries"
		author = "Airbnb"
		id = "04e14811-38be-54eb-8ec0-649d5469078a"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/airbnb/binaryalert/"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/MachO.yara#L1-L7"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "2e992eb7d4ea47c9f61f3a7d8b0b6e37d0423fb08a626eaf2ddea51bfd928dfc"
		score = 75
		quality = 80
		tags = "FILE"

	condition:
		uint32(0)==0xfeedface or uint32(0)==0xcefaedfe or uint32(0)==0xfeedfacf or uint32(0)==0xcffaedfe or uint32(0)==0xcafebabe or uint32(0)==0xbebafeca
}