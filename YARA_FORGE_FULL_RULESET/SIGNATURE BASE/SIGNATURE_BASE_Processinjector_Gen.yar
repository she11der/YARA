import "pe"

rule SIGNATURE_BASE_Processinjector_Gen : HIGHVOL FILE
{
	meta:
		description = "Detects a process injection utility that can be used ofr good and bad purposes"
		author = "Florian Roth (Nextron Systems)"
		id = "9b0b6ac7-8432-5f93-b389-c2356ec75113"
		date = "2018-04-23"
		modified = "2023-12-05"
		reference = "https://github.com/cuckoosandbox/monitor/blob/master/bin/inject.c"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L4198-L4219"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "90d200e79c97911b105e592549bc2c04fb09ce841413c30117d421b45bb9988c"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "456c1c25313ce2e2eedf24fdcd4d37048bcfff193f6848053cbb3b5e82cd527d"

	strings:
		$x1 = "Error injecting remote thread in process:" fullword ascii
		$s5 = "[-] Error getting access to process: %ld!" fullword ascii
		$s6 = "--process-name <name>  Process name to inject" fullword ascii
		$s12 = "No injection target has been provided!" fullword ascii
		$s17 = "[-] An app path is required when not injecting!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <50KB and (pe.imphash()=="d27e0fa013d7ae41be12aaf221e41f9b" or 1 of them ) or 3 of them
}
