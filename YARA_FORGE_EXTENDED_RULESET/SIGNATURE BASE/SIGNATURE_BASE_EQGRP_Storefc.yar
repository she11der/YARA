import "pe"

rule SIGNATURE_BASE_EQGRP_Storefc
{
	meta:
		description = "EQGRP Toolset Firewall - file StoreFc.py"
		author = "Florian Roth (Nextron Systems)"
		id = "48bbf5c9-e884-5126-93a2-d27650409882"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L844-L859"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f07c3ef83808852f70fb5cbc4436d531675344ab74f83888cd70d987c3544cce"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f155cce4eecff8598243a721389046ae2b6ca8ba6cb7b4ac00fd724601a56108"

	strings:
		$x1 = "Usage: StoreFc.py --configFile=<path to xml file> --implantFile=<path to BinStore implant> [--outputFile=<file to write the conf" ascii
		$x2 = "raise Exception, \"Must supply both a config file and implant file.\"" fullword ascii
		$x3 = "This is wrapper for Store.py that FELONYCROWBAR will use. This" fullword ascii

	condition:
		1 of them
}
