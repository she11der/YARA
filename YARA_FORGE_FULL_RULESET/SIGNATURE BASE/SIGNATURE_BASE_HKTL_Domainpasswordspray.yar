import "pe"

rule SIGNATURE_BASE_HKTL_Domainpasswordspray : FILE
{
	meta:
		description = "Detects the Powershell password spray tool DomainPasswordSpray"
		author = "Arnim Rupp"
		id = "890e4514-2846-54f8-8f32-cc9d2a4ef81b"
		date = "2023-01-13"
		modified = "2023-12-05"
		reference = "https://github.com/dafthack/DomainPasswordSpray"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L4671-L4686"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "aa20bf139eff36100624771fe7617c214337ae5ab2e2746143bd8e6cc1b05b4e"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "44d4c0ae5673d2a076f3b5acdc83063aca49d58e6dd7cf73d0b927f83d359247"

	strings:
		$s = "Invoke-DomainPasswordSpray" fullword ascii wide

	condition:
		filesize <100KB and all of them
}
