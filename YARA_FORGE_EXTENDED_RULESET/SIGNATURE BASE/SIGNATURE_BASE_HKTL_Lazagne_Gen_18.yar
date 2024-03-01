import "pe"

rule SIGNATURE_BASE_HKTL_Lazagne_Gen_18
{
	meta:
		description = "Detects Lazagne password extractor hacktool"
		author = "Florian Roth (Nextron Systems)"
		id = "034ea6d8-f5cf-5664-9ff9-24d19403093d"
		date = "2018-12-11"
		modified = "2023-12-05"
		reference = "https://creativecommons.org/licenses/by-nc/4.0/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L4567-L4584"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6f3e895080267a551a3b7a0ba2d4207b31befacbd35d1e6941e1b69d7e2689ce"
		score = 80
		quality = 85
		tags = ""
		hash1 = "51121dd5fbdfe8db7d3a5311e3e9c904d644ff7221b60284c03347938577eecf"

	strings:
		$x1 = "lazagne.config.powershell_execute(" ascii
		$x2 = "creddump7.win32." ascii
		$x3 = "lazagne.softwares.windows.hashdump" ascii
		$x4 = ".softwares.memory.libkeepass.common(" ascii

	condition:
		2 of them
}
