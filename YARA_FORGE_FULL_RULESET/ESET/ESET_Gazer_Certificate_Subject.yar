import "pe"

rule ESET_Gazer_Certificate_Subject
{
	meta:
		description = "Turla Gazer malware"
		author = "ESET Research"
		id = "a7719333-b341-538c-a8ed-5c50b653a765"
		date = "2017-08-30"
		modified = "2017-08-29"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/turla/gazer.yar#L33-L46"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "6e870c9cdcee33769162de62ea143ff401af50b22a63d2f212c44d06f5771dec"
		score = 75
		quality = 80
		tags = ""
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	condition:
		for any i in (0..pe.number_of_signatures-1) : (pe.signatures[i].subject contains "Solid Loop" or pe.signatures[i].subject contains "Ultimate Computer Support")
}
